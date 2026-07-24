#!/usr/bin/env python3
"""Shared, payload-free contracts for the external Round 9 evaluator.

This module is intentionally independent of the Guard Go module.  The installed
broker and the public release verifier share only canonical JSON, signature,
ledger, and aggregate-result validation.  Corpus prompt text is never accepted
by any public evidence schema in this file.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any, Callable


SIGNED_ENVELOPE_SCHEMA = "round9-external-evaluation-signed-envelope/v1"
EVALUATION_SCHEMA = "round9-external-evaluation/v2"
CORPUS_BUNDLE_SCHEMA = "round9-independent-corpus-bundle/v1"
EVALUATOR_AGGREGATE_SCHEMA = "round9-external-evaluator-aggregate/v2"
LEDGER_EVENT_SCHEMA = "round9-external-evaluation-ledger-event/v2"
LEDGER_PROOF_SCHEMA = "round9-protected-git-ledger-proof/v1"
LEDGER_NAMESPACE_PREFIX = "round9-eval-ledger"
DEVELOPMENT_EVIDENCE_SCHEMA = "round9-development-evidence/v1"
COUNTED_MOCK_SCHEMA = "round9-external-counted-mock/v1"
RUNTIME_CHECKS_SCHEMA = "round9-external-cpa-runtime-checks/v1"
DECISION_AUDIT_SCHEMA = "round9-external-decision-audit/v2"

FIXED_NETWORK_BINDING = {
    "host_ip": "127.0.0.1",
    "host_port": 18_394,
    "container_port": 8_317,
}
FIXED_PHASE_PROTOCOL = {
    "single_cpa_container": True,
    "initial_mode": "audit",
    "phase_order": ["audit", "balanced", "strict"],
    "mode_switch_method": "PUT",
    "mode_switch_endpoint": "/v0/management/plugins/cyber-abuse-guard/config",
    "status_endpoint": "/v0/management/plugins/cyber-abuse-guard/status",
    "status_required_after_each_phase_transition": True,
    "mode_switch_authenticated": True,
}
DEVELOPMENT_CLAIM_BOUNDARY = (
    "Candidate-owned development evidence only; it is not independent evidence, "
    "does not authorize production, and executed no third-party repository code."
)
COUNTED_MOCK_CLAIM_BOUNDARY = (
    "Loopback-only CPA, counted-Mock, audit database, controlled restart, lifecycle, "
    "usage-queue, and Raw Capture-disabled observations with synthetic probes only; "
    "no real Provider, production, or real-user traffic claim."
)
COUNTED_MOCK_NOT_OBSERVED: list[str] = []

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ContractError(RuntimeError):
    """Raised when an external-evaluation contract is not exact."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_bytes(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"invalid {label} JSON: {exc}") from exc


def read_bounded_file(path: Path, label: str, *, maximum: int = 1_048_576) -> bytes:
    """Read one regular file without a stat/read growth race or unbounded allocation."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ContractError(f"{label} must be a readable regular non-symlink file") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > maximum:
            raise ContractError(f"{label} size or file type is outside the reviewed bound")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(maximum + 1)
        if len(raw) != info.st_size or len(raw) > maximum:
            raise ContractError(f"{label} changed while being read or exceeds the reviewed bound")
        return raw
    finally:
        os.close(descriptor)


def load_json(path: Path, label: str, *, maximum: int = 1_048_576) -> Any:
    return load_json_bytes(read_bounded_file(path, label, maximum=maximum), label)


def load_canonical_json(path: Path, label: str, *, maximum: int = 1_048_576) -> Any:
    raw = read_bounded_file(path, label, maximum=maximum)
    value = load_json_bytes(raw, label)
    if raw != canonical_bytes(value):
        raise ContractError(f"{label} must be canonical JSON")
    return value


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ContractError(f"{label} keys are not exact")
    return value


def exact_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{label} must be an integer >= {minimum}")
    return value


def exact_bool(value: Any, expected: bool, label: str) -> None:
    if value is not expected:
        raise ContractError(f"{label} must be {str(expected).lower()}")


def require_pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(f"{label} has an invalid format")
    return value


def require_literal(value: Any, expected: str, label: str) -> str:
    if value != expected:
        raise ContractError(f"{label} must be {expected}")
    return expected


def openssl_subprocess_env() -> dict[str, str]:
    """Return the complete environment allowed to reach pinned OpenSSL."""

    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
    }


def openssl_sign(payload: bytes, private_key: Path, openssl: str = "openssl") -> bytes:
    if private_key.is_symlink() or not private_key.is_file():
        raise ContractError("evaluator signing key must be a regular non-symlink file")
    with tempfile.TemporaryDirectory(prefix="cag-r9-sign-") as directory:
        root = Path(directory)
        payload_path = root / "payload.json"
        signature_path = root / "signature.bin"
        payload_path.write_bytes(payload)
        command = [
            openssl,
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key),
            "-in",
            str(payload_path),
            "-out",
            str(signature_path),
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            env=openssl_subprocess_env(),
            check=False,
            timeout=30,
        )
        if completed.returncode != 0:
            raise ContractError("OpenSSL failed to sign the evaluator payload")
        signature = signature_path.read_bytes()
    if len(signature) != 64:
        raise ContractError("Ed25519 evaluator signature is not 64 bytes")
    return signature


def openssl_verify(
    payload: bytes, signature: bytes, public_key: Path, openssl: str = "openssl"
) -> None:
    if public_key.is_symlink() or not public_key.is_file():
        raise ContractError("evaluator public key must be a regular non-symlink file")
    if len(signature) != 64:
        raise ContractError("Ed25519 evaluator signature is not 64 bytes")
    with tempfile.TemporaryDirectory(prefix="cag-r9-verify-") as directory:
        root = Path(directory)
        payload_path = root / "payload.json"
        signature_path = root / "signature.bin"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        command = [
            openssl,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-rawin",
            "-inkey",
            str(public_key),
            "-in",
            str(payload_path),
            "-sigfile",
            str(signature_path),
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            env=openssl_subprocess_env(),
            check=False,
            timeout=30,
        )
        if completed.returncode != 0:
            raise ContractError("external evaluator signature verification failed")


def signed_envelope(
    payload: dict[str, Any],
    private_key: Path,
    key_id: str,
    *,
    openssl: str = "openssl",
) -> dict[str, Any]:
    require_pattern(key_id, IDENTIFIER, "evaluator key id")
    payload_bytes = canonical_bytes(payload)
    signature = openssl_sign(payload_bytes, private_key, openssl)
    return {
        "schema": SIGNED_ENVELOPE_SCHEMA,
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "key_id": key_id,
            "value_base64": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_signed_envelope(
    envelope: Any,
    public_key: Path,
    expected_key_id: str,
    *,
    expected_payload_schema: str | None = None,
    openssl: str = "openssl",
) -> dict[str, Any]:
    value = exact_object(envelope, {"schema", "payload", "signature"}, "signed envelope")
    require_literal(value["schema"], SIGNED_ENVELOPE_SCHEMA, "signed envelope schema")
    signature = exact_object(
        value["signature"], {"algorithm", "key_id", "value_base64"}, "signature"
    )
    require_literal(signature["algorithm"], "ed25519", "signature algorithm")
    require_literal(signature["key_id"], expected_key_id, "signature key id")
    if not isinstance(signature["value_base64"], str):
        raise ContractError("signature value must be base64 text")
    try:
        raw_signature = base64.b64decode(signature["value_base64"], validate=True)
    except ValueError as exc:
        raise ContractError("signature value is not canonical base64") from exc
    payload = value["payload"]
    if not isinstance(payload, dict):
        raise ContractError("signed envelope payload must be an object")
    if expected_payload_schema is not None:
        require_literal(payload.get("schema"), expected_payload_schema, "payload schema")
    openssl_verify(canonical_bytes(payload), raw_signature, public_key, openssl)
    return payload


def challenge_sha256(challenge: str) -> str:
    require_pattern(challenge, HEX64, "workflow challenge")
    return hashlib.sha256(bytes.fromhex(challenge)).hexdigest()


def ledger_namespace(bundle_sha256: str) -> str:
    require_pattern(bundle_sha256, HEX64, "corpus bundle sha256")
    return f"{LEDGER_NAMESPACE_PREFIX}/{bundle_sha256}"


def ledger_ref(namespace: str, event: str) -> str:
    if not namespace.startswith(LEDGER_NAMESPACE_PREFIX + "/"):
        raise ContractError("ledger namespace is outside the Round 9 prefix")
    if event not in {"reserved", "started", "result", "aborted"}:
        raise ContractError("unsupported ledger event")
    return f"refs/tags/{namespace}/{event}"


def validate_candidate(value: Any) -> dict[str, Any]:
    candidate = exact_object(
        value,
        {
            "tag",
            "tag_object_sha",
            "source_version",
            "commit",
            "tree",
            "so_sha256",
            "cpa_version",
            "cpa_commit",
            "classifier_policy_version",
            "classifier_policy_sha256",
            "ruleset_version",
            "ruleset_sha256",
            "ruleset_manifest_sha256",
            "build_metadata_sha256",
            "release_manifest_sha256",
            "phase1_run_id",
            "phase1_run_attempt",
            "phase1_artifact_id",
            "phase1_artifact_digest",
        },
        "candidate",
    )
    require_literal(candidate["tag"], "v0.16-rc.3", "candidate tag")
    require_pattern(candidate["tag_object_sha"], HEX40, "candidate tag object")
    require_literal(candidate["source_version"], "0.16", "candidate source version")
    require_pattern(candidate["commit"], HEX40, "candidate commit")
    require_pattern(candidate["tree"], HEX40, "candidate tree")
    require_pattern(candidate["so_sha256"], HEX64, "candidate SO sha256")
    require_literal(candidate["cpa_version"], "v7.2.95", "candidate CPA version")
    require_literal(
        candidate["cpa_commit"],
        "f71ec0eb6776854457892452cf28c47f0d658251",
        "candidate CPA commit",
    )
    policy = require_pattern(
        candidate["classifier_policy_version"], IDENTIFIER, "classifier policy version"
    )
    if not policy.startswith("classifier-policy-v8"):
        raise ContractError("candidate classifier policy is not a Round 9 v8 identity")
    require_pattern(
        candidate["classifier_policy_sha256"], HEX64, "classifier policy sha256"
    )
    require_literal(candidate["ruleset_version"], "1.0.10", "candidate ruleset version")
    for key in (
        "ruleset_sha256",
        "ruleset_manifest_sha256",
        "build_metadata_sha256",
        "release_manifest_sha256",
    ):
        require_pattern(candidate[key], HEX64, f"candidate {key}")
    exact_int(candidate["phase1_run_id"], "phase1 run id", minimum=1)
    exact_int(candidate["phase1_run_attempt"], "phase1 run attempt", minimum=1)
    exact_int(candidate["phase1_artifact_id"], "phase1 artifact id", minimum=1)
    require_pattern(
        candidate["phase1_artifact_digest"], SHA256_DIGEST, "phase1 artifact digest"
    )
    return candidate


def validate_evaluator(value: Any) -> dict[str, Any]:
    evaluator = exact_object(
        value,
        {
            "version",
            "sha256",
            "core_sha256",
            "broker_sha256",
            "key_id",
            "execution_mode",
        },
        "evaluator",
    )
    require_pattern(evaluator["version"], IDENTIFIER, "evaluator version")
    require_pattern(evaluator["sha256"], HEX64, "evaluator sha256")
    require_pattern(evaluator["core_sha256"], HEX64, "evaluator core sha256")
    require_pattern(evaluator["broker_sha256"], HEX64, "evaluator broker sha256")
    require_pattern(evaluator["key_id"], IDENTIFIER, "evaluator key id")
    require_literal(
        evaluator["execution_mode"],
        "EXTERNAL_ROOT_OWNED_BLACK_BOX_CPA",
        "evaluator execution mode",
    )
    return evaluator


def validate_corpus(value: Any) -> dict[str, Any]:
    corpus = exact_object(
        value,
        {
            "evaluation_id",
            "bundle_sha256",
            "bundle_manifest_sha256",
            "benign_manifest_sha256",
            "benign_cases_sha256",
            "malicious_manifest_sha256",
            "malicious_cases_sha256",
            "author_key_id",
            "plaintext_in_repository",
        },
        "corpus",
    )
    require_pattern(corpus["evaluation_id"], IDENTIFIER, "evaluation id")
    for key in (
        "bundle_sha256",
        "bundle_manifest_sha256",
        "benign_manifest_sha256",
        "benign_cases_sha256",
        "malicious_manifest_sha256",
        "malicious_cases_sha256",
    ):
        require_pattern(corpus[key], HEX64, f"corpus {key}")
    require_pattern(corpus["author_key_id"], IDENTIFIER, "corpus author key id")
    exact_bool(corpus["plaintext_in_repository"], False, "plaintext_in_repository")
    return corpus


def validate_digest_binding(
    value: Any,
    label: str,
    *,
    schema: str | None = None,
    maximum: int = 4_194_304,
) -> dict[str, Any]:
    keys = {"bytes", "sha256"}
    if schema is not None:
        keys.add("schema")
    binding = exact_object(value, keys, label)
    if schema is not None:
        require_literal(binding["schema"], schema, f"{label} schema")
    size = exact_int(binding["bytes"], f"{label} bytes", minimum=1)
    if size > maximum:
        raise ContractError(f"{label} exceeds the reviewed size bound")
    digest = require_pattern(binding["sha256"], HEX64, f"{label} sha256")
    if digest == "0" * 64:
        raise ContractError(f"{label} sha256 cannot be the all-zero sentinel")
    return binding


def validate_development_evidence(
    value: Any,
    *,
    expected_candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = exact_object(
        value,
        {
            "schema",
            "state",
            "candidate",
            "runtime",
            "platform",
            "corpus",
            "audit_contract",
            "machine_reports",
            "producer_logs",
            "claim_boundary",
        },
        "Round 9 development evidence",
    )
    require_literal(evidence["schema"], DEVELOPMENT_EVIDENCE_SCHEMA, "development evidence schema")
    require_literal(evidence["state"], "PASS", "development evidence state")
    require_literal(evidence["runtime"], "go1.26.4", "development evidence runtime")
    require_literal(evidence["platform"], "linux/amd64", "development evidence platform")
    require_literal(
        evidence["claim_boundary"],
        DEVELOPMENT_CLAIM_BOUNDARY,
        "development evidence claim boundary",
    )

    candidate = exact_object(
        evidence["candidate"],
        {"tag", "tag_object_sha", "commit", "tree", "classifier", "ruleset"},
        "development evidence candidate",
    )
    require_literal(candidate["tag"], "v0.16-rc.3", "development candidate tag")
    require_pattern(candidate["tag_object_sha"], HEX40, "development candidate tag object")
    require_pattern(candidate["commit"], HEX40, "development candidate commit")
    require_pattern(candidate["tree"], HEX40, "development candidate tree")
    classifier = exact_object(
        candidate["classifier"], {"version", "sha256"}, "development candidate classifier"
    )
    classifier_version = require_pattern(
        classifier["version"], IDENTIFIER, "development classifier version"
    )
    if not classifier_version.startswith("classifier-policy-v8"):
        raise ContractError("development classifier is not the Round 9 v8 identity")
    require_pattern(classifier["sha256"], HEX64, "development classifier sha256")
    ruleset = exact_object(
        candidate["ruleset"], {"version", "sha256"}, "development candidate ruleset"
    )
    require_literal(ruleset["version"], "1.0.10", "development ruleset version")
    require_pattern(ruleset["sha256"], HEX64, "development ruleset sha256")
    if expected_candidate is not None:
        expected = validate_candidate(expected_candidate)
        candidate_projection = {
            "tag": expected["tag"],
            "tag_object_sha": expected["tag_object_sha"],
            "commit": expected["commit"],
            "tree": expected["tree"],
            "classifier": {
                "version": expected["classifier_policy_version"],
                "sha256": expected["classifier_policy_sha256"],
            },
            "ruleset": {
                "version": expected["ruleset_version"],
                "sha256": expected["ruleset_sha256"],
            },
        }
        if candidate != candidate_projection:
            raise ContractError("development evidence candidate binding differs")

    corpus = exact_object(
        evidence["corpus"],
        {"development_benign", "paired_malicious", "public_adversarial"},
        "development evidence corpus",
    )
    benign = exact_object(
        corpus["development_benign"],
        {
            "name",
            "manifest",
            "cases",
            "unique_semantic_samples",
            "serialized_route_executions",
            "blocked_semantic_samples",
            "blocked_route_executions",
        },
        "development benign evidence",
    )
    require_literal(benign["name"], "round9-development-benign-v1", "development benign name")
    validate_digest_binding(benign["manifest"], "development benign manifest")
    validate_digest_binding(benign["cases"], "development benign cases", maximum=8_388_608)
    if (
        exact_int(benign["unique_semantic_samples"], "development benign samples") != 1_200
        or exact_int(benign["serialized_route_executions"], "development benign routes") != 7_200
        or exact_int(benign["blocked_semantic_samples"], "development benign semantic blocks") != 0
        or exact_int(benign["blocked_route_executions"], "development benign route blocks") != 0
    ):
        raise ContractError("development benign evidence is not the frozen 1200/7200 zero-block contract")

    paired = exact_object(
        corpus["paired_malicious"],
        {
            "name",
            "source_report_schema",
            "manifest_version",
            "manifest",
            "cases",
            "label_audit",
            "benign_manifest",
            "benign_cases",
            "unique_semantic_samples",
            "semantic_blocked",
            "serialized_route_executions",
            "enforcement_route_executions",
            "audit_route_executions",
            "passed_route_executions",
            "audit_allowed_route_executions",
            "audit_policy_blocked",
            "recall_basis_points",
            "per_category",
        },
        "paired malicious development evidence",
    )
    require_literal(
        paired["name"], "round9-development-paired-malicious-v3", "paired malicious name"
    )
    require_literal(
        paired["source_report_schema"],
        "round9-development-paired-malicious-report/v3",
        "paired malicious source schema",
    )
    if exact_int(paired["manifest_version"], "paired malicious manifest version") != 2:
        raise ContractError("paired malicious manifest version differs")
    for key, maximum in (
        ("manifest", 4_194_304),
        ("cases", 8_388_608),
        ("label_audit", 262_144),
        ("benign_manifest", 4_194_304),
        ("benign_cases", 8_388_608),
    ):
        validate_digest_binding(paired[key], f"paired malicious {key}", maximum=maximum)
    samples = exact_int(paired["unique_semantic_samples"], "paired malicious samples")
    blocked = exact_int(paired["semantic_blocked"], "paired malicious blocked")
    routes = exact_int(paired["serialized_route_executions"], "paired malicious routes")
    enforcement_routes = exact_int(
        paired["enforcement_route_executions"],
        "paired malicious enforcement routes",
    )
    audit_routes = exact_int(
        paired["audit_route_executions"], "paired malicious Audit routes"
    )
    passed_routes = exact_int(paired["passed_route_executions"], "paired malicious passed routes")
    audit_allowed = exact_int(
        paired["audit_allowed_route_executions"],
        "paired malicious Audit allowed routes",
    )
    audit_blocked = exact_int(
        paired["audit_policy_blocked"], "paired malicious Audit policy blocks"
    )
    recall = exact_int(paired["recall_basis_points"], "paired malicious recall")
    if (
        samples != 120
        or blocked > samples
        or routes != 960
        or enforcement_routes != routes
        or audit_routes != 0
        or passed_routes != enforcement_routes
        or audit_allowed != 0
        or audit_blocked != 0
        or recall != blocked * 10_000 // samples
        or recall != 10_000
    ):
        raise ContractError("paired malicious development evidence misses the frozen recall contract")
    per_category = paired["per_category"]
    if not isinstance(per_category, dict) or len(per_category) < 2:
        raise ContractError("paired malicious per-category evidence is incomplete")
    category_samples = 0
    category_blocked = 0
    for name, item in per_category.items():
        require_pattern(name, IDENTIFIER, f"paired malicious category {name}")
        row = exact_object(
            item,
            {
                "samples",
                "blocked",
                "recall_basis_points",
                "wilson_lower_bound_basis_points",
                "wilson_upper_bound_basis_points",
            },
            f"paired malicious category {name}",
        )
        item_samples = exact_int(row["samples"], f"paired malicious {name} samples", minimum=1)
        item_blocked = exact_int(row["blocked"], f"paired malicious {name} blocked")
        item_recall = exact_int(row["recall_basis_points"], f"paired malicious {name} recall")
        lower, upper = wilson_interval_95(item_blocked, item_samples)
        if (
            item_blocked > item_samples
            or item_recall != item_blocked * 10_000 // item_samples
            or item_recall != 10_000
            or exact_int(row["wilson_lower_bound_basis_points"], f"paired malicious {name} Wilson lower")
            != round(lower * 10_000)
            or exact_int(row["wilson_upper_bound_basis_points"], f"paired malicious {name} Wilson upper")
            != round(upper * 10_000)
        ):
            raise ContractError(f"paired malicious category {name} misses the recall contract")
        category_samples += item_samples
        category_blocked += item_blocked
    if category_samples != samples or category_blocked != blocked:
        raise ContractError("paired malicious category totals differ")

    public = exact_object(
        corpus["public_adversarial"],
        {
            "name",
            "manifest",
            "development_only",
            "independent_holdout",
            "third_party_code_executed",
            "metrics",
        },
        "public adversarial development evidence",
    )
    require_literal(public["name"], "round9-public-adversarial-v5", "public corpus name")
    validate_digest_binding(public["manifest"], "public corpus manifest")
    exact_bool(public["development_only"], True, "public corpus development_only")
    exact_bool(public["independent_holdout"], False, "public corpus independent_holdout")
    exact_bool(public["third_party_code_executed"], False, "public corpus third_party_code_executed")
    expected_public_metrics = {
        "payload_records": 24,
        "formal_unique_payloads": 23,
        "candidate_carriers": 1,
        "candidate_executions": 1,
        "not_provided": 0,
        "scenario_payload_executions": 24,
        "serialized_route_executions": 120,
        "direct_blocked": 12,
        "direct_allowed": 12,
        "quoted_blocked": 0,
        "historical_blocked": 0,
        "system_blocked": 0,
        "tool_blocked": 0,
    }
    public_metrics = exact_object(
        public["metrics"], set(expected_public_metrics), "public adversarial metrics"
    )
    if public_metrics != expected_public_metrics:
        raise ContractError("public adversarial development metrics differ")

    audit = exact_object(
        evidence["audit_contract"],
        {
            "schema_version",
            "raw_capture_schema_version",
            "decision_kinds",
            "malicious_block_requires_eligible_winner",
            "incomplete_has_no_malicious_winner",
        },
        "development audit contract",
    )
    if (
        exact_int(audit["schema_version"], "development audit schema") != 6
        or exact_int(audit["raw_capture_schema_version"], "development Raw Capture schema") != 4
        or audit["decision_kinds"]
        != [
            "allow_clean",
            "audit_eligible_malicious_text",
            "audit_ineligible_risk",
            "block_incomplete_inspection",
            "block_malicious_text",
            "block_opaque_media",
            "block_subject_risk",
        ]
    ):
        raise ContractError("development audit schema identity differs")
    exact_bool(
        audit["malicious_block_requires_eligible_winner"],
        True,
        "malicious_block_requires_eligible_winner",
    )
    exact_bool(
        audit["incomplete_has_no_malicious_winner"],
        True,
        "incomplete_has_no_malicious_winner",
    )

    reports = exact_object(
        evidence["machine_reports"],
        {"development_benign", "paired_malicious", "public_adversarial", "audit_contract"},
        "development machine reports",
    )
    report_schemas = {
        "development_benign": ("round9-development-benign-corpus-report/v1", 4_194_304),
        "paired_malicious": ("round9-development-paired-malicious-machine-report/v1", 4_194_304),
        "public_adversarial": ("round9-public-adversarial-report/v5", 262_144),
        "audit_contract": ("round9-audit-contract-report/v1", 262_144),
    }
    for name, (schema, maximum) in report_schemas.items():
        validate_digest_binding(
            reports[name], f"development machine report {name}", schema=schema, maximum=maximum
        )
    logs = exact_object(
        evidence["producer_logs"],
        {"paired_malicious", "public_adversarial", "audit_contract"},
        "development producer logs",
    )
    for name, maximum in {
        "paired_malicious": 4_194_304,
        "public_adversarial": 262_144,
        "audit_contract": 4_194_304,
    }.items():
        validate_digest_binding(logs[name], f"development producer log {name}", maximum=maximum)
    return evidence


def validate_network_binding(value: Any) -> dict[str, Any]:
    binding = exact_object(value, set(FIXED_NETWORK_BINDING), "CPA network binding")
    if binding != FIXED_NETWORK_BINDING:
        raise ContractError("CPA network binding must be exactly 127.0.0.1:18394 -> 8317/tcp")
    return binding


def validate_phase_protocol(value: Any) -> dict[str, Any]:
    protocol = exact_object(value, set(FIXED_PHASE_PROTOCOL), "CPA phase protocol")
    if protocol != FIXED_PHASE_PROTOCOL:
        raise ContractError(
            "CPA phase protocol must use one authenticated container in Audit, Balanced, then Strict order"
        )
    return protocol


def validate_runtime_checks(value: Any) -> dict[str, Any]:
    checks = exact_object(
        value,
        {
            "schema",
            "state",
            "phase",
            "audit_database",
            "restart_recovery",
            "panic_recovery",
            "usage_queue",
            "raw_capture",
            "lifecycle",
        },
        "CPA runtime checks",
    )
    require_literal(checks["schema"], RUNTIME_CHECKS_SCHEMA, "runtime checks schema")
    require_literal(checks["state"], "PASS", "runtime checks state")
    if checks["phase"] not in {"preflight", "post_evaluation"}:
        raise ContractError("runtime checks phase is invalid")

    database = exact_object(
        checks["audit_database"],
        {
            "observed",
            "quick_check",
            "schema_version",
            "migration_versions",
            "wal_checkpoint_passed",
            "evaluation_event_delta",
        },
        "runtime audit database",
    )
    exact_bool(database["observed"], True, "runtime database observed")
    require_literal(database["quick_check"], "ok", "runtime database quick_check")
    if exact_int(database["schema_version"], "runtime audit schema") != 6:
        raise ContractError("runtime audit schema must be v6")
    if database["migration_versions"] != [1, 2, 3, 4, 5, 6]:
        raise ContractError("runtime audit migration history is incomplete")
    exact_bool(
        database["wal_checkpoint_passed"], True, "runtime WAL checkpoint passed"
    )
    event_delta = exact_int(
        database["evaluation_event_delta"], "runtime evaluation event delta"
    )

    restart = exact_object(
        checks["restart_recovery"],
        {
            "observed",
            "controlled_restart_count",
            "unexpected_restart_count",
            "post_restart_mode_verified",
        },
        "runtime restart recovery",
    )
    exact_bool(restart["observed"], True, "runtime restart observed")
    if exact_int(restart["controlled_restart_count"], "controlled restart count") != 1:
        raise ContractError("runtime checks require exactly one controlled restart")
    if exact_int(restart["unexpected_restart_count"], "unexpected restart count") != 0:
        raise ContractError("runtime checks observed an unexpected restart")
    require_literal(
        restart["post_restart_mode_verified"],
        "audit",
        "post-restart verified mode",
    )

    panic = exact_object(
        checks["panic_recovery"],
        {
            "observed",
            "probe_passed",
            "panic_count",
            "fatal_count",
            "plugin_error_count",
            "request_body_log_markers",
        },
        "runtime panic recovery",
    )
    exact_bool(panic["observed"], True, "runtime panic recovery observed")
    exact_bool(panic["probe_passed"], True, "runtime panic recovery probe")
    for key in (
        "panic_count",
        "fatal_count",
        "plugin_error_count",
        "request_body_log_markers",
    ):
        if exact_int(panic[key], f"runtime {key}") != 0:
            raise ContractError(f"runtime lifecycle contains a non-zero {key}")

    usage = exact_object(
        checks["usage_queue"],
        {
            "observed",
            "allowed_request_delta",
            "blocked_request_delta",
            "evaluation_allowed_delta",
            "evaluation_blocked_delta",
            "post_evaluation_quiet",
        },
        "runtime usage queue",
    )
    exact_bool(usage["observed"], True, "runtime usage queue observed")
    if exact_int(usage["allowed_request_delta"], "allowed usage queue delta") != 1:
        raise ContractError("allowed runtime probe did not enqueue exactly one usage record")
    if exact_int(usage["blocked_request_delta"], "blocked usage queue delta") != 0:
        raise ContractError("blocked runtime probe unexpectedly enqueued usage")
    evaluation_allowed = exact_int(
        usage["evaluation_allowed_delta"], "evaluation allowed usage delta"
    )
    evaluation_blocked = exact_int(
        usage["evaluation_blocked_delta"], "evaluation blocked usage delta"
    )
    exact_bool(
        usage["post_evaluation_quiet"], True, "post-evaluation usage queue quiet"
    )

    raw_capture = exact_object(
        checks["raw_capture"],
        {
            "observed",
            "default_disabled",
            "normal_request_records",
            "normal_request_plaintext_persisted",
            "evaluation_request_records",
            "evaluation_plaintext_persisted",
        },
        "runtime Raw Capture",
    )
    exact_bool(raw_capture["observed"], True, "runtime Raw Capture observed")
    exact_bool(raw_capture["default_disabled"], True, "Raw Capture default disabled")
    if exact_int(raw_capture["normal_request_records"], "normal Raw Capture records") != 0:
        raise ContractError("a normal runtime probe created a Raw Capture record")
    exact_bool(
        raw_capture["normal_request_plaintext_persisted"],
        False,
        "normal request plaintext persisted",
    )
    if exact_int(
        raw_capture["evaluation_request_records"], "evaluation Raw Capture records"
    ) != 0:
        raise ContractError("external evaluation created a Raw Capture record")
    exact_bool(
        raw_capture["evaluation_plaintext_persisted"],
        False,
        "evaluation plaintext persisted",
    )

    lifecycle = exact_object(
        checks["lifecycle"],
        {"observed", "exit_code", "oom_killed", "unexpected_restart_count"},
        "runtime lifecycle",
    )
    exact_bool(lifecycle["observed"], True, "runtime lifecycle observed")
    if exact_int(lifecycle["exit_code"], "runtime exit code") != 0:
        raise ContractError("controlled CPA stop was not clean")
    exact_bool(lifecycle["oom_killed"], False, "runtime OOM killed")
    if exact_int(lifecycle["unexpected_restart_count"], "lifecycle restart count") != 0:
        raise ContractError("runtime lifecycle observed an unexpected restart")
    if checks["phase"] == "preflight":
        if event_delta != 0 or evaluation_allowed != 0 or evaluation_blocked != 0:
            raise ContractError("runtime preflight contains evaluation deltas")
    elif event_delta < 1 or evaluation_allowed + evaluation_blocked < event_delta:
        raise ContractError("post-evaluation runtime counters cannot cover the persisted audit events")
    return checks


def validate_execution(value: Any) -> dict[str, Any]:
    execution = exact_object(
        value,
        {
            "workflow_run_id",
            "workflow_run_attempt",
            "challenge_sha256",
            "route_order_seed_sha256",
            "sandbox_id",
            "daemon_id",
            "probe_image_id",
            "cpa_version",
            "cpa_commit",
            "cpa_image_id",
            "counted_mock_image_id",
            "model",
            "scan_limit_bytes",
            "sandbox_adapter_sha256",
            "sandbox_adapter_config_sha256",
            "docker_sandbox_sha256",
            "network_binding",
            "phase_protocol",
            "production_accessed",
            "real_provider_contacted",
        },
        "execution",
    )
    exact_int(execution["workflow_run_id"], "workflow run id", minimum=1)
    exact_int(execution["workflow_run_attempt"], "workflow run attempt", minimum=1)
    require_pattern(execution["challenge_sha256"], HEX64, "challenge sha256")
    require_pattern(
        execution["route_order_seed_sha256"], HEX64, "route order seed sha256"
    )
    if execution["route_order_seed_sha256"] != execution["challenge_sha256"]:
        raise ContractError("route-order seed does not bind the reserved workflow challenge")
    require_pattern(execution["sandbox_id"], IDENTIFIER, "sandbox id")
    require_pattern(execution["daemon_id"], IDENTIFIER, "daemon id")
    require_pattern(execution["probe_image_id"], SHA256_DIGEST, "probe image id")
    require_literal(execution["cpa_version"], "v7.2.95", "CPA version")
    require_literal(
        execution["cpa_commit"],
        "f71ec0eb6776854457892452cf28c47f0d658251",
        "CPA commit",
    )
    require_pattern(execution["cpa_image_id"], SHA256_DIGEST, "CPA image id")
    require_pattern(
        execution["counted_mock_image_id"], SHA256_DIGEST, "counted Mock image id"
    )
    model = execution["model"]
    if (
        not isinstance(model, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", model) is None
        or any(
            marker in model.casefold()
            for marker in ("round9", "eval", "mock", "corpus", "holdout", "test")
        )
    ):
        raise ContractError("execution model is not an ordinary model identity")
    if exact_int(execution["scan_limit_bytes"], "execution scan limit", minimum=4096) != 16_384:
        raise ContractError("execution scan limit must remain exactly 16 KiB")
    for key in (
        "sandbox_adapter_sha256",
        "sandbox_adapter_config_sha256",
        "docker_sandbox_sha256",
    ):
        require_pattern(execution[key], HEX64, f"execution {key}")
    validate_network_binding(execution["network_binding"])
    validate_phase_protocol(execution["phase_protocol"])
    exact_bool(execution["production_accessed"], False, "production_accessed")
    exact_bool(execution["real_provider_contacted"], False, "real_provider_contacted")
    return execution


def wilson_interval_95(successes: int, total: int) -> tuple[float, float]:
    if total <= 0 or successes < 0 or successes > total:
        raise ContractError("Wilson interval inputs are invalid")
    z = 1.959963984540054
    probability = successes / total
    z2 = z * z
    denominator = 1 + z2 / total
    center = probability + z2 / (2 * total)
    margin = z * (
        probability * (1 - probability) / total + z2 / (4 * total * total)
    ) ** 0.5
    return max(0.0, (center - margin) / denominator), min(
        1.0, (center + margin) / denominator
    )


def exact_count_map(
    value: Any,
    label: str,
    *,
    expected_keys: set[str] | None = None,
    expected_total: int | None = None,
) -> dict[str, int]:
    if not isinstance(value, dict) or not value:
        raise ContractError(f"{label} must be a non-empty object")
    if expected_keys is not None and set(value) != expected_keys:
        raise ContractError(f"{label} key set is invalid")
    result: dict[str, int] = {}
    for key, item in value.items():
        if not isinstance(key, str) or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", key
        ) is None:
            raise ContractError(f"{label} contains an invalid key")
        result[key] = exact_int(item, f"{label}.{key}")
    if expected_total is not None and sum(result.values()) != expected_total:
        raise ContractError(f"{label} total is invalid")
    return result


def validate_decision_audit(value: Any) -> dict[str, Any]:
    audit = exact_object(
        value,
        {
            "schema",
            "state",
            "observed",
            "expectations_sha256",
            "expectation_count",
            "required_expectation_count",
            "optional_expectation_count",
            "matched_count",
            "optional_persisted_count",
            "optional_missing_count",
            "unexpected_event_count",
            "decision_kind_counts",
            "group_counts",
            "subject_state_rows",
            "incomplete_malicious_category_count",
            "incomplete_winner_count",
            "correlation_sha256",
            "correlation_samples",
        },
        "external decision audit",
    )
    require_literal(audit["schema"], DECISION_AUDIT_SCHEMA, "decision audit schema")
    require_literal(audit["state"], "PASS", "decision audit state")
    exact_bool(audit["observed"], True, "decision audit observed")
    require_pattern(
        audit["expectations_sha256"], HEX64, "decision audit expectations sha256"
    )
    expectation_count = exact_int(
        audit["expectation_count"], "decision audit expectation count", minimum=2
    )
    required_count = exact_int(
        audit["required_expectation_count"],
        "decision audit required expectation count",
        minimum=1,
    )
    optional_count = exact_int(
        audit["optional_expectation_count"],
        "decision audit optional expectation count",
    )
    matched_count = exact_int(audit["matched_count"], "decision audit matched count")
    optional_persisted = exact_int(
        audit["optional_persisted_count"], "decision audit optional persisted count"
    )
    optional_missing = exact_int(
        audit["optional_missing_count"], "decision audit optional missing count"
    )
    if (
        required_count + optional_count != expectation_count
        or optional_persisted + optional_missing != optional_count
        or matched_count != required_count + optional_persisted
    ):
        raise ContractError("decision audit required/optional persistence counts are inconsistent")
    if exact_int(audit["unexpected_event_count"], "decision audit unexpected events") != 0:
        raise ContractError("decision audit contains unexpected evaluation events")
    decisions = exact_count_map(
        audit["decision_kind_counts"],
        "decision audit decision kinds",
        expected_keys={
            "audit_eligible_malicious_text",
            "audit_ineligible_risk",
            "block_malicious_text",
            "block_incomplete_inspection",
        },
        expected_total=matched_count,
    )
    groups = exact_count_map(
        audit["group_counts"],
        "decision audit groups",
        expected_keys={
            "benign",
            "malicious_audit",
            "malicious_enforcement",
            "incomplete_non_strict",
            "strict_incomplete",
        },
        expected_total=matched_count,
    )
    if groups["incomplete_non_strict"] != 2 or groups["strict_incomplete"] != 1:
        raise ContractError("decision audit incomplete groups differ from the fixed phase matrix")
    if (
        decisions["audit_ineligible_risk"] != 2 + optional_persisted
        or decisions["block_incomplete_inspection"] != 1
    ):
        raise ContractError("decision audit incomplete/optional decision kinds differ")
    if groups["benign"] != optional_persisted:
        raise ContractError("decision audit benign group does not bind optional persistence")
    for key, label in (
        ("subject_state_rows", "decision audit subject state"),
        ("incomplete_malicious_category_count", "decision audit incomplete malicious category"),
        ("incomplete_winner_count", "decision audit incomplete winner"),
    ):
        if exact_int(audit[key], label) != 0:
            raise ContractError(f"{label} must remain zero")
    require_pattern(audit["correlation_sha256"], HEX64, "decision audit correlation sha256")
    samples = audit["correlation_samples"]
    if not isinstance(samples, list) or not 1 <= len(samples) <= 16:
        raise ContractError("decision audit correlation samples are outside the reviewed bound")
    sample_ids: set[str] = set()
    for index, item in enumerate(samples):
        sample = exact_object(
            item,
            {
                "request_id_hmac_sha256",
                "request_hash_hmac_sha256",
                "event_id_sha256",
                "mode",
                "decision_kind",
            },
            f"decision audit correlation sample {index}",
        )
        request_id = require_pattern(
            sample["request_id_hmac_sha256"], HEX64, "decision audit request id"
        )
        if request_id in sample_ids:
            raise ContractError("decision audit correlation samples contain a duplicate id")
        sample_ids.add(request_id)
        require_pattern(
            sample["request_hash_hmac_sha256"],
            HEX64,
            "decision audit keyed request correlation",
        )
        require_pattern(sample["event_id_sha256"], HEX64, "decision audit event id sha256")
        if sample["mode"] not in {"audit", "balanced", "strict"}:
            raise ContractError("decision audit sample mode is invalid")
        if sample["decision_kind"] not in decisions:
            raise ContractError("decision audit sample decision kind is invalid")
    return audit


def validate_metrics(value: Any) -> dict[str, Any]:
    metrics = exact_object(
        value,
        {
            "route_order",
            "route_histogram",
            "benign",
            "malicious",
            "incomplete",
            "runtime_checks",
            "decision_audit",
        },
        "metrics",
    )
    route_order = exact_object(
        metrics["route_order"],
        {
            "algorithm",
            "seed_sha256",
            "phase_order",
            "phase_permutation_sha256",
            "phase_route_executions",
            "mode_status_verified",
            "mode_switch_authenticated",
            "mode_switch_negative_auth_verified",
            "effective_config_sha256",
            "route_executions",
        },
        "route order",
    )
    require_literal(
        route_order["algorithm"],
        "hmac_sha256_challenge_sequential_phase_order_v3",
        "route-order algorithm",
    )
    require_pattern(route_order["seed_sha256"], HEX64, "route-order seed sha256")
    if route_order["phase_order"] != ["audit", "balanced", "strict"]:
        raise ContractError(
            "route-order phases must be exactly Audit, Balanced, then Strict"
        )
    phase_permutations = exact_object(
        route_order["phase_permutation_sha256"],
        {"audit", "balanced", "strict"},
        "route-order phase permutations",
    )
    for mode in ("audit", "balanced", "strict"):
        require_pattern(
            phase_permutations[mode], HEX64, f"route-order {mode} permutation sha256"
        )
    phase_route_executions = exact_object(
        route_order["phase_route_executions"],
        {"audit", "balanced", "strict"},
        "route-order phase executions",
    )
    mode_status = exact_object(
        route_order["mode_status_verified"],
        {"audit", "balanced", "strict"},
        "route-order verified modes",
    )
    for mode in ("audit", "balanced", "strict"):
        exact_bool(mode_status[mode], True, f"{mode} status verified")
    exact_bool(
        route_order["mode_switch_authenticated"],
        True,
        "authenticated mode switches",
    )
    negative_auth = exact_object(
        route_order["mode_switch_negative_auth_verified"],
        {"balanced", "strict"},
        "mode-switch negative-auth verification",
    )
    for mode in ("balanced", "strict"):
        exact_bool(negative_auth[mode], True, f"{mode} negative-auth mode switch")
    effective_hashes = exact_object(
        route_order["effective_config_sha256"],
        {"audit", "balanced", "strict"},
        "effective configuration identities",
    )
    for mode in ("audit", "balanced", "strict"):
        require_pattern(
            effective_hashes[mode], HEX64, f"{mode} effective configuration sha256"
        )
    route_order_total = exact_int(
        route_order["route_executions"], "route-order execution count", minimum=2
    )

    benign = exact_object(
        metrics["benign"],
        {
            "unique_semantic_samples",
            "serialized_route_executions",
            "blocked",
            "hard_policy_blocked",
            "wilson_upper_bound_ppm",
            "category_counts",
            "language_counts",
            "protocol_counts",
            "stream_counts",
            "mode_counts",
            "carrier_counts",
            "upstream_delta",
            "usage_delta",
            "cag_policy_block_delta",
        },
        "benign metrics",
    )
    benign_samples = exact_int(
        benign["unique_semantic_samples"], "benign samples", minimum=600
    )
    benign_routes = exact_int(
        benign["serialized_route_executions"],
        "benign routes",
        minimum=benign_samples * 12,
    )
    if benign_routes != benign_samples * 12:
        raise ContractError("benign routes must remain twelve per semantic sample")
    if exact_int(benign["blocked"], "benign blocked") != 0:
        raise ContractError("external benign evaluation contains a block")
    if exact_int(benign["hard_policy_blocked"], "benign hard blocks") != 0:
        raise ContractError("external benign evaluation contains a hard block")
    wilson_ppm = exact_int(benign["wilson_upper_bound_ppm"], "benign Wilson ppm")
    expected_wilson = round(1_000_000 * 1.959963984540054**2 / (benign_samples + 1.959963984540054**2))
    if wilson_ppm != expected_wilson:
        raise ContractError("benign Wilson upper bound is not the frozen 95% zero-event bound")
    exact_count_map(
        benign["category_counts"], "benign category counts", expected_total=benign_samples
    )
    exact_count_map(
        benign["language_counts"],
        "benign language counts",
        expected_keys={"en", "zh"},
        expected_total=benign_samples,
    )
    exact_count_map(
        benign["protocol_counts"],
        "benign protocol counts",
        expected_keys={"openai_chat", "openai_responses"},
        expected_total=benign_routes,
    )
    exact_count_map(
        benign["stream_counts"],
        "benign stream counts",
        expected_keys={"stream", "nonstream"},
        expected_total=benign_routes,
    )
    exact_count_map(
        benign["mode_counts"],
        "benign mode counts",
        expected_keys={"audit", "balanced", "strict"},
        expected_total=benign_routes,
    )
    exact_count_map(
        benign["carrier_counts"],
        "benign carrier counts",
        expected_keys={"current_user_direct"},
        expected_total=benign_routes,
    )
    benign_upstream = exact_int(benign["upstream_delta"], "benign upstream delta")
    benign_usage = exact_int(benign["usage_delta"], "benign usage delta")
    benign_cag = exact_int(benign["cag_policy_block_delta"], "benign CAG block delta")
    if (
        benign_upstream + benign_cag != benign_routes
        or benign_usage != benign_upstream
        or benign_cag != benign["blocked"]
        or benign["hard_policy_blocked"] > benign_cag
    ):
        raise ContractError("benign counted-Mock/CAG accounting is contradictory")

    malicious = exact_object(
        metrics["malicious"],
        {
            "unique_semantic_samples",
            "semantic_blocked",
            "serialized_route_executions",
            "enforcement_route_executions",
            "audit_route_executions",
            "passed_route_executions",
            "audit_allowed_route_executions",
            "audit_policy_blocked",
            "recall_basis_points",
            "wilson_lower_bound_basis_points",
            "wilson_upper_bound_basis_points",
            "per_category",
            "category_counts",
            "language_counts",
            "protocol_counts",
            "stream_counts",
            "mode_counts",
            "carrier_counts",
            "upstream_delta",
            "usage_delta",
            "cag_policy_block_delta",
            "failure_id_hmac_sha256",
            "enforcement_blocks_per_semantic_sample",
        },
        "malicious metrics",
    )
    malicious_samples = exact_int(
        malicious["unique_semantic_samples"], "malicious samples", minimum=90
    )
    malicious_routes = exact_int(
        malicious["serialized_route_executions"],
        "malicious routes",
        minimum=malicious_samples * 12,
    )
    if malicious_routes != malicious_samples * 12:
        raise ContractError("malicious routes must remain twelve per semantic sample")
    enforcement_routes = exact_int(
        malicious["enforcement_route_executions"],
        "malicious enforcement routes",
        minimum=malicious_samples * 8,
    )
    audit_routes = exact_int(
        malicious["audit_route_executions"],
        "malicious audit routes",
        minimum=malicious_samples * 4,
    )
    if (
        enforcement_routes != malicious_samples * 8
        or audit_routes != malicious_samples * 4
        or enforcement_routes + audit_routes != malicious_routes
    ):
        raise ContractError("malicious Audit/enforcement route partition is invalid")
    blocked = exact_int(malicious["semantic_blocked"], "malicious blocked")
    passed = exact_int(malicious["passed_route_executions"], "malicious passed routes")
    audit_allowed = exact_int(
        malicious["audit_allowed_route_executions"],
        "malicious Audit allowed routes",
    )
    audit_blocked = exact_int(
        malicious["audit_policy_blocked"], "malicious Audit policy blocks"
    )
    recall = exact_int(malicious["recall_basis_points"], "malicious recall basis points")
    expected_recall = blocked * 10_000 // malicious_samples
    if (
        blocked > malicious_samples
        or passed > enforcement_routes
        or audit_allowed != audit_routes
        or audit_blocked != 0
        or recall != expected_recall
        or recall < 9500
    ):
        raise ContractError("malicious external evaluation misses the recall contract")
    overall_lower, overall_upper = wilson_interval_95(blocked, malicious_samples)
    if (
        exact_int(
            malicious["wilson_lower_bound_basis_points"],
            "malicious Wilson lower bound",
        )
        != round(overall_lower * 10_000)
        or exact_int(
            malicious["wilson_upper_bound_basis_points"],
            "malicious Wilson upper bound",
        )
        != round(overall_upper * 10_000)
    ):
        raise ContractError("malicious aggregate Wilson interval is not count-derived")
    per_category = malicious["per_category"]
    if not isinstance(per_category, dict) or len(per_category) != 9:
        raise ContractError("malicious per-category metrics must contain nine categories")
    category_sample_total = 0
    category_blocked_total = 0
    for category, item in per_category.items():
        require_pattern(category, IDENTIFIER, f"malicious category {category}")
        row = exact_object(
            item,
            {
                "samples",
                "blocked",
                "recall_basis_points",
                "wilson_lower_bound_basis_points",
                "wilson_upper_bound_basis_points",
            },
            f"malicious category {category}",
        )
        samples = exact_int(row["samples"], f"{category} samples", minimum=1)
        category_blocked = exact_int(row["blocked"], f"{category} blocked")
        category_recall = exact_int(
            row["recall_basis_points"], f"{category} recall basis points"
        )
        expected_category_recall = category_blocked * 10_000 // samples
        category_lower, category_upper = wilson_interval_95(category_blocked, samples)
        if (
            category_blocked > samples
            or category_recall != expected_category_recall
            or category_recall < 9500
            or exact_int(
                row["wilson_lower_bound_basis_points"],
                f"{category} Wilson lower bound",
            )
            != round(category_lower * 10_000)
            or exact_int(
                row["wilson_upper_bound_basis_points"],
                f"{category} Wilson upper bound",
            )
            != round(category_upper * 10_000)
        ):
            raise ContractError(f"malicious category {category} misses the recall floor")
        category_sample_total += samples
        category_blocked_total += category_blocked
    if category_sample_total != malicious_samples or category_blocked_total != blocked:
        raise ContractError("malicious per-category totals do not bind the aggregate")
    exact_count_map(
        malicious["category_counts"],
        "malicious category counts",
        expected_total=malicious_samples,
    )
    exact_count_map(
        malicious["language_counts"],
        "malicious language counts",
        expected_keys={"en", "zh"},
        expected_total=malicious_samples,
    )
    exact_count_map(
        malicious["protocol_counts"],
        "malicious protocol counts",
        expected_keys={"openai_chat", "openai_responses"},
        expected_total=malicious_routes,
    )
    exact_count_map(
        malicious["stream_counts"],
        "malicious stream counts",
        expected_keys={"stream", "nonstream"},
        expected_total=malicious_routes,
    )
    exact_count_map(
        malicious["mode_counts"],
        "malicious mode counts",
        expected_keys={"audit", "balanced", "strict"},
        expected_total=malicious_routes,
    )
    exact_count_map(
        malicious["carrier_counts"],
        "malicious carrier counts",
        expected_keys={"current_user_direct"},
        expected_total=malicious_routes,
    )
    if malicious["category_counts"] != {
        category: per_category[category]["samples"] for category in per_category
    }:
        raise ContractError("malicious category counts differ from per-category metrics")
    if set(malicious["language_counts"]) != {"en", "zh"}:
        raise ContractError("malicious language counts must contain exactly en and zh")
    malicious_upstream = exact_int(
        malicious["upstream_delta"], "malicious upstream delta"
    )
    malicious_usage = exact_int(malicious["usage_delta"], "malicious usage delta")
    malicious_cag = exact_int(
        malicious["cag_policy_block_delta"], "malicious CAG block delta"
    )
    if (
        malicious_upstream + malicious_cag != malicious_routes
        or malicious_usage != malicious_upstream
        or malicious_cag != passed
        or malicious_upstream != audit_routes
        or malicious_usage != audit_routes
    ):
        raise ContractError("malicious counted-Mock/CAG accounting is contradictory")
    failure_ids = malicious["failure_id_hmac_sha256"]
    if not isinstance(failure_ids, list):
        raise ContractError("malicious failure identifiers must be a list")
    for index, item in enumerate(failure_ids):
        require_pattern(item, HEX64, f"malicious failure id {index}")
    if len(failure_ids) != malicious_samples - blocked or len(set(failure_ids)) != len(failure_ids):
        raise ContractError("malicious failure identifiers do not bind failed semantic samples")
    semantic_histogram = exact_count_map(
        malicious["enforcement_blocks_per_semantic_sample"],
        "malicious enforcement blocks per semantic sample",
        expected_keys={str(index) for index in range(9)},
        expected_total=malicious_samples,
    )
    if (
        sum(int(bucket) * count for bucket, count in semantic_histogram.items()) != passed
        or semantic_histogram["8"] != blocked
        or sum(semantic_histogram[str(index)] for index in range(8)) != len(failure_ids)
    ):
        raise ContractError("malicious semantic recall is not mechanically bound to route outcomes")

    incomplete = exact_object(
        metrics["incomplete"],
        {
            "request_hmac_sha256",
            "request_bytes",
            "scan_limit_bytes",
            "valid_json",
            "protocol",
            "stream",
            "carrier",
            "audit",
            "balanced",
            "strict",
        },
        "incomplete metrics",
    )
    require_pattern(
        incomplete["request_hmac_sha256"],
        HEX64,
        "incomplete execution-scoped request HMAC",
    )
    request_bytes = exact_int(incomplete["request_bytes"], "incomplete request bytes", minimum=1)
    scan_limit = exact_int(incomplete["scan_limit_bytes"], "incomplete scan limit", minimum=1)
    if request_bytes <= scan_limit:
        raise ContractError("incomplete probe does not exceed the reviewed scan limit")
    exact_bool(incomplete["valid_json"], True, "incomplete valid_json")
    require_literal(incomplete["protocol"], "openai_chat", "incomplete protocol")
    exact_bool(incomplete["stream"], False, "incomplete stream")
    require_literal(
        incomplete["carrier"], "current_user_direct", "incomplete carrier"
    )
    audit_incomplete = exact_object(
        incomplete["audit"],
        {"policy_blocked", "upstream_delta", "usage_delta"},
        "Audit incomplete observation",
    )
    balanced_incomplete = exact_object(
        incomplete["balanced"],
        {"policy_blocked", "upstream_delta", "usage_delta"},
        "balanced incomplete observation",
    )
    strict_incomplete = exact_object(
        incomplete["strict"],
        {"policy_blocked", "upstream_delta", "usage_delta"},
        "strict incomplete observation",
    )
    exact_bool(
        audit_incomplete["policy_blocked"],
        False,
        "Audit incomplete policy_blocked",
    )
    exact_bool(
        balanced_incomplete["policy_blocked"],
        False,
        "balanced incomplete policy_blocked",
    )
    exact_bool(
        strict_incomplete["policy_blocked"],
        True,
        "strict incomplete policy_blocked",
    )
    if (
        exact_int(audit_incomplete["upstream_delta"], "Audit incomplete upstream") != 1
        or exact_int(audit_incomplete["usage_delta"], "Audit incomplete usage") != 1
        or exact_int(balanced_incomplete["upstream_delta"], "balanced incomplete upstream") != 1
        or exact_int(balanced_incomplete["usage_delta"], "balanced incomplete usage") != 1
        or exact_int(strict_incomplete["upstream_delta"], "strict incomplete upstream") != 0
        or exact_int(strict_incomplete["usage_delta"], "strict incomplete usage") != 0
    ):
        raise ContractError("incomplete counted-Mock disposition accounting failed")
    histogram = exact_object(
        metrics["route_histogram"],
        {"benign", "malicious", "incomplete"},
        "route histogram",
    )
    full_route_keys = {
        f"{mode}|openai_{protocol}|{stream}"
        for mode in ("audit", "balanced", "strict")
        for protocol in ("chat", "responses")
        for stream in ("stream", "nonstream")
    }
    incomplete_route_keys = {
        f"{mode}|openai_chat|nonstream" for mode in ("audit", "balanced", "strict")
    }

    def validate_route_rows(
        rows_value: Any, label: str, expected_keys: set[str], executions_each: int
    ) -> tuple[int, int, int, int]:
        if not isinstance(rows_value, dict) or set(rows_value) != expected_keys:
            raise ContractError(f"{label} key set does not bind the fixed route matrix")
        totals = [0, 0, 0, 0]
        for route, item in rows_value.items():
            row = exact_object(
                item,
                {"executions", "policy_blocked", "upstream_delta", "usage_delta"},
                f"{label} {route}",
            )
            values = [
                exact_int(row["executions"], f"{label} {route} executions"),
                exact_int(row["policy_blocked"], f"{label} {route} blocks"),
                exact_int(row["upstream_delta"], f"{label} {route} upstream"),
                exact_int(row["usage_delta"], f"{label} {route} usage"),
            ]
            if values[0] != executions_each or any(value > values[0] for value in values[1:]):
                raise ContractError(f"{label} {route} counters are contradictory")
            if values[1] + values[2] != values[0] or values[2] != values[3]:
                raise ContractError(f"{label} {route} counted-Mock accounting differs")
            totals = [left + right for left, right in zip(totals, values)]
        return tuple(totals)  # type: ignore[return-value]

    benign_hist = validate_route_rows(
        histogram["benign"], "benign route histogram", full_route_keys, benign_samples
    )
    malicious_hist = validate_route_rows(
        histogram["malicious"],
        "malicious route histogram",
        full_route_keys,
        malicious_samples,
    )
    incomplete_hist = validate_route_rows(
        histogram["incomplete"],
        "incomplete route histogram",
        incomplete_route_keys,
        1,
    )
    if benign_hist != (benign_routes, benign_cag, benign_upstream, benign_usage):
        raise ContractError("benign route histogram does not bind the aggregate")
    if malicious_hist != (
        malicious_routes,
        malicious_cag,
        malicious_upstream,
        malicious_usage,
    ):
        raise ContractError("malicious route histogram does not bind the aggregate")
    if incomplete_hist != (3, 1, 2, 2):
        raise ContractError("incomplete route histogram does not bind the three phase outcomes")
    if route_order_total != benign_routes + malicious_routes + 3:
        raise ContractError("route-order execution count does not bind all external requests")
    expected_phase_routes = benign_samples * 4 + malicious_samples * 4 + 1
    for mode in ("audit", "balanced", "strict"):
        if (
            exact_int(
                phase_route_executions[mode], f"route-order {mode} execution count", minimum=1
            )
            != expected_phase_routes
        ):
            raise ContractError("route-order phase execution count does not bind the fixed matrix")
    if sum(phase_route_executions.values()) != route_order_total:
        raise ContractError("route-order phase totals differ from the aggregate")
    runtime = validate_runtime_checks(metrics["runtime_checks"])
    require_literal(runtime["phase"], "post_evaluation", "runtime checks phase")
    decision_audit = validate_decision_audit(metrics["decision_audit"])
    optional_persisted = decision_audit["optional_persisted_count"]
    expected_decisions = {
        "audit_eligible_malicious_text": malicious_routes - malicious_cag,
        "audit_ineligible_risk": 2 + optional_persisted,
        "block_malicious_text": malicious_cag,
        "block_incomplete_inspection": 1,
    }
    expected_groups = {
        "benign": optional_persisted,
        "malicious_audit": audit_routes,
        "malicious_enforcement": enforcement_routes,
        "incomplete_non_strict": 2,
        "strict_incomplete": 1,
    }
    if (
        decision_audit["decision_kind_counts"] != expected_decisions
        or decision_audit["group_counts"] != expected_groups
        or decision_audit["expectation_count"] != route_order_total
        or decision_audit["required_expectation_count"] != malicious_routes + 3
        or decision_audit["optional_expectation_count"] != benign_routes
        or decision_audit["optional_missing_count"] != benign_routes - optional_persisted
        or runtime["audit_database"]["evaluation_event_delta"]
        != decision_audit["matched_count"]
        or runtime["usage_queue"]["evaluation_allowed_delta"]
        != benign_upstream + malicious_upstream + 2
        or runtime["usage_queue"]["evaluation_blocked_delta"]
        != benign_cag + malicious_cag + 1
    ):
        raise ContractError("decision/runtime evidence does not mechanically bind route outcomes")
    return metrics


def derive_counted_mock(
    metrics_value: Any,
    execution_value: Any,
) -> dict[str, Any]:
    """Mechanically derive the only publishable counted-Mock PASS object."""

    metrics = validate_metrics(metrics_value)
    execution = validate_execution(execution_value)
    benign = metrics["benign"]
    malicious = metrics["malicious"]
    incomplete = metrics["incomplete"]
    route_order = metrics["route_order"]
    runtime_checks = load_json_bytes(
        canonical_bytes(metrics["runtime_checks"]), "derived runtime checks"
    )
    decision_audit = load_json_bytes(
        canonical_bytes(metrics["decision_audit"]), "derived decision audit"
    )
    return {
        "schema": COUNTED_MOCK_SCHEMA,
        "state": "PASS",
        "cpa": {
            "version": execution["cpa_version"],
            "commit": execution["cpa_commit"],
            "image_id": execution["cpa_image_id"],
        },
        "mock": {
            "contract": "round9-counted-mock/v1",
            "image_id": execution["counted_mock_image_id"],
            "request_body_retention": False,
        },
        "execution": {
            "sandbox_id": execution["sandbox_id"],
            "daemon_id": execution["daemon_id"],
            "probe_image_id": execution["probe_image_id"],
            "model": execution["model"],
            "scan_limit_bytes": execution["scan_limit_bytes"],
            "production_accessed": execution["production_accessed"],
            "real_provider_contacted": execution["real_provider_contacted"],
        },
        "host_results": {
            "network_binding": dict(execution["network_binding"]),
            "phase_order": list(route_order["phase_order"]),
            "phase_route_executions": dict(route_order["phase_route_executions"]),
            "mode_status_verified": dict(route_order["mode_status_verified"]),
            "mode_switch_authenticated": route_order["mode_switch_authenticated"],
            "benign": {
                "route_executions": benign["serialized_route_executions"],
                "policy_block_delta": benign["cag_policy_block_delta"],
                "hard_policy_block_delta": benign["hard_policy_blocked"],
                "upstream_delta": benign["upstream_delta"],
                "usage_delta": benign["usage_delta"],
            },
            "malicious": {
                "semantic_samples": malicious["unique_semantic_samples"],
                "semantic_blocked": malicious["semantic_blocked"],
                "route_executions": malicious["serialized_route_executions"],
                "enforcement_route_executions": malicious[
                    "enforcement_route_executions"
                ],
                "audit_route_executions": malicious["audit_route_executions"],
                "audit_allowed_route_executions": malicious[
                    "audit_allowed_route_executions"
                ],
                "audit_policy_blocked": malicious["audit_policy_blocked"],
                "policy_block_delta": malicious["cag_policy_block_delta"],
                "upstream_delta": malicious["upstream_delta"],
                "usage_delta": malicious["usage_delta"],
            },
            "incomplete": {
                "audit": dict(incomplete["audit"]),
                "balanced": dict(incomplete["balanced"]),
                "strict": dict(incomplete["strict"]),
            },
            "runtime_checks": runtime_checks,
            "decision_audit": decision_audit,
        },
        "not_observed": list(COUNTED_MOCK_NOT_OBSERVED),
        "claim_boundary": COUNTED_MOCK_CLAIM_BOUNDARY,
    }


def validate_counted_mock(
    value: Any,
    metrics: Any,
    execution: Any,
) -> dict[str, Any]:
    counted = exact_object(
        value,
        {
            "schema",
            "state",
            "cpa",
            "mock",
            "execution",
            "host_results",
            "not_observed",
            "claim_boundary",
        },
        "counted Mock evidence",
    )
    expected = derive_counted_mock(metrics, execution)
    if counted != expected:
        raise ContractError("counted Mock evidence is not the mechanical metrics/execution derivation")
    return counted


def validate_ledger_binding(value: Any, corpus: dict[str, Any]) -> dict[str, Any]:
    ledger = exact_object(
        value,
        {"repository", "namespace", "reserved_ref", "started_ref", "result_ref"},
        "ledger",
    )
    require_pattern(ledger["repository"], REPOSITORY, "ledger repository")
    expected_namespace = ledger_namespace(corpus["bundle_sha256"])
    require_literal(ledger["namespace"], expected_namespace, "ledger namespace")
    for event in ("reserved", "started", "result"):
        require_literal(
            ledger[f"{event}_ref"], ledger_ref(expected_namespace, event), f"ledger {event} ref"
        )
    return ledger


def validate_privacy(value: Any) -> dict[str, Any]:
    privacy = exact_object(
        value,
        {
            "raw_prompts_in_result",
            "raw_responses_in_result",
            "request_bodies_in_logs",
            "failure_identifier_policy",
        },
        "privacy",
    )
    exact_bool(privacy["raw_prompts_in_result"], False, "raw_prompts_in_result")
    exact_bool(privacy["raw_responses_in_result"], False, "raw_responses_in_result")
    exact_bool(privacy["request_bodies_in_logs"], False, "request_bodies_in_logs")
    require_literal(
        privacy["failure_identifier_policy"],
        "challenge_hmac_sha256_case_id_only",
        "failure identifier policy",
    )
    return privacy


def validate_evaluation_payload(
    payload: Any,
    *,
    expected_candidate: dict[str, Any] | None = None,
    challenge: str | None = None,
) -> dict[str, Any]:
    value = exact_object(
        payload,
        {
            "schema",
            "state",
            "candidate",
            "evaluator",
            "corpus",
            "execution",
            "ledger",
            "development_evidence",
            "counted_mock",
            "metrics",
            "privacy",
        },
        "external evaluation payload",
    )
    require_literal(value["schema"], EVALUATION_SCHEMA, "evaluation schema")
    require_literal(value["state"], "PASS", "evaluation state")
    candidate = validate_candidate(value["candidate"])
    if expected_candidate is not None and candidate != expected_candidate:
        raise ContractError("external evaluation candidate binding differs")
    evaluator = validate_evaluator(value["evaluator"])
    corpus = validate_corpus(value["corpus"])
    execution = validate_execution(value["execution"])
    if challenge is not None and execution["challenge_sha256"] != challenge_sha256(challenge):
        raise ContractError("external evaluation challenge binding differs")
    validate_ledger_binding(value["ledger"], corpus)
    validate_development_evidence(value["development_evidence"], expected_candidate=candidate)
    metrics = validate_metrics(value["metrics"])
    if metrics["route_order"]["seed_sha256"] != execution["route_order_seed_sha256"]:
        raise ContractError("route-order metrics do not bind the execution challenge")
    validate_counted_mock(value["counted_mock"], metrics, execution)
    validate_privacy(value["privacy"])
    if evaluator["key_id"] == corpus["author_key_id"]:
        raise ContractError("corpus author and evaluator execution keys must be distinct")
    return value


def validate_ledger_event_payload(value: Any, event: str) -> dict[str, Any]:
    payload = exact_object(
        value,
        {
            "schema",
            "event",
            "repository",
            "namespace",
            "candidate",
            "evaluator",
            "corpus",
            "execution",
            "development_evidence",
            "counted_mock",
            "evaluation_envelope_sha256",
        },
        f"ledger {event} payload",
    )
    require_literal(payload["schema"], LEDGER_EVENT_SCHEMA, "ledger event schema")
    require_literal(payload["event"], event, "ledger event")
    require_pattern(payload["repository"], REPOSITORY, "ledger event repository")
    candidate = validate_candidate(payload["candidate"])
    validate_evaluator(payload["evaluator"])
    corpus = validate_corpus(payload["corpus"])
    execution = validate_execution(payload["execution"])
    validate_development_evidence(payload["development_evidence"], expected_candidate=candidate)
    expected_namespace = ledger_namespace(corpus["bundle_sha256"])
    require_literal(payload["namespace"], expected_namespace, "ledger event namespace")
    digest = payload["evaluation_envelope_sha256"]
    if event == "result":
        require_pattern(digest, HEX64, "result evaluation envelope sha256")
        if not isinstance(payload["counted_mock"], dict):
            raise ContractError("result ledger event must bind counted Mock evidence")
    elif digest is not None:
        raise ContractError("non-result ledger event cannot bind an evaluation envelope")
    elif payload["counted_mock"] is not None:
        raise ContractError("non-result ledger event cannot bind counted Mock evidence")
    _ = candidate, execution
    return payload


def validate_ledger_proof(
    value: Any,
    evaluation_envelope: dict[str, Any],
    evaluation_payload: dict[str, Any],
    public_key: Path,
    expected_key_id: str,
    *,
    remote_loader: Callable[[str, str], tuple[str, str]] | None = None,
) -> dict[str, Any]:
    proof = exact_object(
        value,
        {"schema", "repository", "namespace", "refs", "aborted_ref_absent"},
        "ledger proof",
    )
    require_literal(proof["schema"], LEDGER_PROOF_SCHEMA, "ledger proof schema")
    ledger = validate_ledger_binding(evaluation_payload["ledger"], evaluation_payload["corpus"])
    require_literal(proof["repository"], ledger["repository"], "ledger proof repository")
    require_literal(proof["namespace"], ledger["namespace"], "ledger proof namespace")
    exact_bool(proof["aborted_ref_absent"], True, "aborted_ref_absent")
    refs = exact_object(proof["refs"], {"reserved", "started", "result"}, "ledger proof refs")
    evaluation_digest = sha256_bytes(canonical_bytes(evaluation_envelope))
    for event in ("reserved", "started", "result"):
        entry = exact_object(
            refs[event], {"ref", "tag_object_sha", "message_sha256", "envelope"}, f"ledger proof {event}"
        )
        require_literal(entry["ref"], ledger[f"{event}_ref"], f"ledger proof {event} ref")
        require_pattern(entry["tag_object_sha"], HEX40, f"ledger proof {event} tag object")
        require_pattern(entry["message_sha256"], HEX64, f"ledger proof {event} message sha256")
        event_payload = verify_signed_envelope(
            entry["envelope"], public_key, expected_key_id, expected_payload_schema=LEDGER_EVENT_SCHEMA
        )
        validate_ledger_event_payload(event_payload, event)
        if (
            event_payload["repository"] != ledger["repository"]
            or event_payload["namespace"] != ledger["namespace"]
            or event_payload["candidate"] != evaluation_payload["candidate"]
            or event_payload["evaluator"] != evaluation_payload["evaluator"]
            or event_payload["corpus"] != evaluation_payload["corpus"]
            or event_payload["execution"] != evaluation_payload["execution"]
            or event_payload["development_evidence"]
            != evaluation_payload["development_evidence"]
            or event_payload["counted_mock"]
            != (evaluation_payload["counted_mock"] if event == "result" else None)
        ):
            raise ContractError(f"ledger {event} event binding differs from evaluation")
        message = canonical_bytes(entry["envelope"])
        if sha256_bytes(message) != entry["message_sha256"]:
            raise ContractError(f"ledger {event} message digest differs")
        if remote_loader is not None:
            remote_sha, remote_message = remote_loader(ledger["repository"], entry["ref"])
            if remote_sha != entry["tag_object_sha"] or remote_message.encode("utf-8") != message:
                raise ContractError(f"remote ledger {event} tag differs from proof")
    result_payload = refs["result"]["envelope"]["payload"]
    if result_payload["evaluation_envelope_sha256"] != evaluation_digest:
        raise ContractError("ledger result event does not bind the exact evaluation envelope")
    return proof


def public_key_sha256(path: Path) -> str:
    return sha256_file(path)


def require_root_owned_regular(path: Path, label: str, *, mode_mask: int = 0o022) -> None:
    info = path.lstat()
    if path.is_symlink() or not path.is_file():
        raise ContractError(f"{label} must be a regular non-symlink file")
    if info.st_uid != 0:
        raise ContractError(f"{label} must be owned by root")
    if info.st_mode & mode_mask:
        raise ContractError(f"{label} must not be group/world writable")


def atomic_write(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
