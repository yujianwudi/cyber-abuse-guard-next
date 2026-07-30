#!/usr/bin/env python3
"""Assemble and validate the closed Round 9 Host evidence envelope.

The protected Host workflow may reuse the already-reviewed Linux counted-Mock
execution engine as an implementation detail, but publication trusts only this
new envelope.  The envelope binds the exact candidate, classifier and ruleset
identities, frozen corpus statistics, counted-Mock results, and GitHub workflow
execution identity without embedding request text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "round9-host-evidence/v1"
CONTRACT_SCHEMA = "round9-evaluation-contract/v1"
TAG = "v0.16-rc.4"
CPA_VERSION = "v7.2.109"
CPA_COMMIT = "928478e4b91533cec05a763bfac3edad9c3e76cf"
VALIDATION_SCOPE = "CPA_V7_2_109_COUNTED_MOCK_AND_FROZEN_CORPUS_ADMISSION"
CPA_HOST_IP = "127.0.0.1"
CPA_HOST_PORT = 18394
CPA_CONTAINER_PORT = 8317
REPOSITORY = "yujianwudi/cyber-abuse-guard-next"
RELEASE_WORKFLOW = ".github/workflows/round9-release-rc.yml"
HOST_WORKFLOW = ".github/workflows/round9-host-validation.yml"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
PAIRED_SOURCE_SCHEMA = re.compile(
    r"round9-development-paired-malicious-report/v(?P<version>[0-9]+)"
)
PAIRED_CORPUS = re.compile(
    r"round9-development-paired-malicious-v(?P<version>[0-9]+)"
)
POLICY_VERSION = re.compile(
    r'^const ClassifierPolicyVersion = "([A-Za-z0-9._-]+)"$', re.MULTILINE
)
POLICY_SHA256 = re.compile(
    r'^const ClassifierPolicySHA256 = "([0-9a-f]{64})"$', re.MULTILINE
)
PUBLIC_DEVELOPMENT_CORPUS = "round9-public-adversarial-v13"
PUBLIC_DEVELOPMENT_REPORT_SCHEMA = "round9-public-adversarial-report/v13"
PUBLIC_DEVELOPMENT_MANIFEST = {
    "bytes": 481448,
    "sha256": "91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6",
}
PUBLIC_DEVELOPMENT_METRICS = {
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
    "system_blocked": 2,
    "tool_blocked": 2,
}
PUBLIC_HOST_CONTRACT = {
    "payload_records": 24,
    "unique_historical_payloads": 8,
    "unique_branch_head_payloads": 1,
    "unique_current_prompt_like_payloads": 14,
    "unique_formal_payloads": 23,
    "unmerged_candidate_carriers": 1,
    "nondefault_branch_candidate_carriers": 5,
    "release_assets_reviewed": 16,
    "release_assets_with_prompt_entries": 4,
    "release_asset_metadata_records": 199,
    "candidate_carrier_executions": 1,
    "candidate_carriers_not_provided": 0,
    "scenario_payload_executions": 24,
    "serialized_route_executions": 120,
    "direct_active_blocked": 12,
    "direct_active_allowed": 12,
    "quoted_allowed": 24,
    "historical_allowed": 24,
    "system_allowed": 24,
    "tool_allowed": 24,
}


class ContractError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ContractError(message)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def read_json(path: Path, *, maximum: int, canonical: bool = True) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail(f"required JSON is not a regular file: {path}")
    raw = path.read_bytes()
    if not 2 <= len(raw) <= maximum:
        fail(f"JSON size is outside the reviewed bound: {path}")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ContractError) as exc:
        fail(f"invalid JSON {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON root must be an object: {path}")
    if canonical and raw != canonical_bytes(value):
        fail(f"JSON must be canonical UTF-8 without trailing bytes: {path}")
    return value


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} must contain exactly {sorted(expected)}")
    return value


def exact_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        fail(f"{label} must be an integer >= {minimum}")
    return value


def exact_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        fail(f"{label} must be a boolean")
    return value


def exact_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty string")
    return value


def require_hex(value: Any, label: str, pattern: re.Pattern[str] = HEX64) -> str:
    text = exact_string(value, label)
    if pattern.fullmatch(text) is None:
        fail(f"{label} is not a canonical lowercase identity")
    return text


def require_sidecar(path: Path, target: Path) -> str:
    if path.is_symlink() or not path.is_file():
        fail(f"SHA-256 sidecar is not a regular file: {path}")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    expected = f"{digest}  {target.name}\n".encode()
    if path.read_bytes() != expected:
        fail(f"SHA-256 sidecar does not bind exact bytes: {path}")
    return digest


def policy_identity(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        fail("classifier policy identity source is not a regular file")
    text = path.read_text(encoding="utf-8")
    version = POLICY_VERSION.findall(text)
    digest = POLICY_SHA256.findall(text)
    if len(version) != 1 or len(digest) != 1:
        fail("classifier policy identity source is not exact")
    if not version[0].startswith("classifier-policy-v9"):
        fail("Round 9 requires classifier-policy-v9 or a reviewed v9 successor")
    return {"version": version[0], "sha256": digest[0]}


def ruleset_identity(manifest_path: Path, sidecar_path: Path) -> dict[str, str]:
    manifest = read_json(manifest_path, maximum=262144, canonical=False)
    exact_keys(
        manifest,
        {"schema_version", "plugin_version", "ruleset_version", "ruleset_sha256", "files"},
        "ruleset manifest",
    )
    version = exact_string(manifest["ruleset_version"], "ruleset version")
    if version != "1.0.10":
        fail("Round 9 ruleset identity must be 1.0.10")
    digest = require_hex(manifest["ruleset_sha256"], "ruleset SHA-256")
    require_sidecar(sidecar_path, manifest_path)
    return {"version": version, "sha256": digest}


def validate_benign_section(
    value: Any, label: str, *, minimum_samples: int, require_wilson: bool
) -> dict[str, Any]:
    keys = {
        "corpus_sha256",
        "ground_truth_sha256",
        "unique_semantic_samples",
        "serialized_route_executions",
        "blocked",
        "hard_policy_blocked",
    }
    if require_wilson:
        keys.add("wilson_upper_bound_ppm")
    section = exact_keys(value, keys, label)
    require_hex(section["corpus_sha256"], f"{label}.corpus_sha256")
    require_hex(section["ground_truth_sha256"], f"{label}.ground_truth_sha256")
    unique = exact_int(
        section["unique_semantic_samples"],
        f"{label}.unique_semantic_samples",
        minimum=minimum_samples,
    )
    routes = exact_int(
        section["serialized_route_executions"],
        f"{label}.serialized_route_executions",
        minimum=unique,
    )
    if exact_int(section["blocked"], f"{label}.blocked") != 0:
        fail(f"{label} contains a normal request block")
    if exact_int(section["hard_policy_blocked"], f"{label}.hard_policy_blocked") != 0:
        fail(f"{label} contains a normal hard-policy block")
    if require_wilson:
        wilson = exact_int(
            section["wilson_upper_bound_ppm"],
            f"{label}.wilson_upper_bound_ppm",
            minimum=1,
        )
        # 0/600 at 95% two-sided Wilson is about 6361 ppm.  Larger samples
        # naturally produce a smaller bound; looser post-hoc bounds are refused.
        maximum = round(1_000_000 * 1.96**2 / (unique + 1.96**2))
        if wilson != maximum:
            fail(f"{label} Wilson bound must equal the predeclared 95% calculation")
    return section


def validate_malicious_section(value: Any, label: str) -> dict[str, Any]:
    section = exact_keys(
        value,
        {
            "corpus_sha256",
            "ground_truth_sha256",
            "samples",
            "eligible_samples",
            "blocked",
            "recall_basis_points",
            "wilson_lower_bound_basis_points",
        },
        label,
    )
    require_hex(section["corpus_sha256"], f"{label}.corpus_sha256")
    require_hex(section["ground_truth_sha256"], f"{label}.ground_truth_sha256")
    samples = exact_int(section["samples"], f"{label}.samples", minimum=1)
    eligible = exact_int(
        section["eligible_samples"], f"{label}.eligible_samples", minimum=1
    )
    blocked = exact_int(section["blocked"], f"{label}.blocked", minimum=0)
    if eligible > samples or blocked > eligible:
        fail(f"{label} sample counts are contradictory")
    recall = exact_int(
        section["recall_basis_points"], f"{label}.recall_basis_points", minimum=0
    )
    if recall > 10000 or recall != blocked * 10000 // eligible or recall < 9500:
        fail(f"{label} recall does not meet the frozen >=95% contract")
    lower = exact_int(
        section["wilson_lower_bound_basis_points"],
        f"{label}.wilson_lower_bound_basis_points",
        minimum=0,
    )
    if lower > recall:
        fail(f"{label} Wilson lower bound exceeds observed recall")
    return section


def validate_paired_section(value: Any) -> dict[str, Any]:
    section = exact_keys(
        value,
        {
            "corpus_name",
            "source_report_schema",
            "corpus_manifest_version",
            "corpus_manifest_sha256",
            "corpus_cases_sha256",
            "label_audit",
            "benign_corpus_manifest_sha256",
            "benign_corpus_cases_sha256",
            "samples",
            "blocked",
            "serialized_route_executions",
            "passed_route_executions",
            "recall_basis_points",
            "wilson_lower_bound_basis_points",
            "wilson_upper_bound_basis_points",
            "per_category",
        },
        "paired_malicious",
    )
    schema = exact_string(section["source_report_schema"], "paired source report schema")
    corpus = exact_string(section["corpus_name"], "paired corpus name")
    schema_match = PAIRED_SOURCE_SCHEMA.fullmatch(schema)
    corpus_match = PAIRED_CORPUS.fullmatch(corpus)
    if (
        schema_match is None
        or corpus_match is None
        or int(schema_match.group("version")) < 3
        or int(corpus_match.group("version")) < 3
        or schema_match.group("version") != corpus_match.group("version")
    ):
        fail("paired malicious evidence must use a non-rejected v3-or-newer corpus")
    if exact_int(
        section["corpus_manifest_version"],
        "paired_malicious.corpus_manifest_version",
    ) != 2:
        fail("paired malicious evidence must bind manifest version 2")
    label_audit = exact_keys(
        section["label_audit"], {"bytes", "sha256"}, "paired_malicious.label_audit"
    )
    exact_int(label_audit["bytes"], "paired_malicious.label_audit.bytes", minimum=512)
    require_hex(label_audit["sha256"], "paired_malicious.label_audit.sha256")
    for key in (
        "corpus_manifest_sha256",
        "corpus_cases_sha256",
        "benign_corpus_manifest_sha256",
        "benign_corpus_cases_sha256",
    ):
        require_hex(section[key], f"paired_malicious.{key}")
    samples = exact_int(section["samples"], "paired_malicious.samples", minimum=120)
    blocked = exact_int(section["blocked"], "paired_malicious.blocked")
    routes = exact_int(
        section["serialized_route_executions"],
        "paired_malicious.serialized_route_executions",
        minimum=samples * 8,
    )
    passed = exact_int(
        section["passed_route_executions"],
        "paired_malicious.passed_route_executions",
    )
    recall = exact_int(
        section["recall_basis_points"], "paired_malicious.recall_basis_points"
    )
    if (
        blocked > samples
        or recall != blocked * 10000 // samples
        or recall != 10000
        or routes != samples * 8
        or passed != routes
    ):
        fail("paired malicious aggregate recall/route evidence failed")
    lower = exact_int(
        section["wilson_lower_bound_basis_points"],
        "paired_malicious.wilson_lower_bound_basis_points",
    )
    upper = exact_int(
        section["wilson_upper_bound_basis_points"],
        "paired_malicious.wilson_upper_bound_basis_points",
    )
    expected_lower, expected_upper = wilson_interval(blocked, samples)
    if lower != round(expected_lower * 10000) or upper != round(expected_upper * 10000):
        fail("paired malicious aggregate Wilson interval is not count-derived")
    per_category = section["per_category"]
    if not isinstance(per_category, dict) or len(per_category) < 2:
        fail("paired malicious per-category evidence is incomplete")
    category_samples_total = 0
    category_blocked_total = 0
    for category, value in per_category.items():
        item = exact_keys(
            value,
            {
                "samples",
                "blocked",
                "recall_basis_points",
                "wilson_lower_bound_basis_points",
                "wilson_upper_bound_basis_points",
            },
            f"paired_malicious.per_category.{category}",
        )
        count = exact_int(item["samples"], f"paired category {category}.samples", minimum=1)
        hits = exact_int(item["blocked"], f"paired category {category}.blocked")
        category_recall = exact_int(
            item["recall_basis_points"], f"paired category {category}.recall"
        )
        category_lower, category_upper = wilson_interval(hits, count)
        if (
            hits > count
            or category_recall != hits * 10000 // count
            or category_recall != 10000
            or exact_int(
                item["wilson_lower_bound_basis_points"],
                f"paired category {category}.wilson_lower",
            )
            != round(category_lower * 10000)
            or exact_int(
                item["wilson_upper_bound_basis_points"],
                f"paired category {category}.wilson_upper",
            )
            != round(category_upper * 10000)
        ):
            fail(f"paired malicious category evidence failed: {category}")
        category_samples_total += count
        category_blocked_total += hits
    if category_samples_total != samples or category_blocked_total != blocked:
        fail("paired malicious per-category totals do not match the aggregate")
    return section


def validate_contract(value: Any, policy: dict[str, str], ruleset: dict[str, str]) -> dict[str, Any]:
    contract = exact_keys(
        value,
        {
            "schema",
            "decision",
            "candidate",
            "audit_contract",
            "development_benign",
            "independent_benign",
            "paired_malicious",
            "independent_malicious",
            "public_adversarial",
            "route_matrix",
        },
        "Round 9 evaluation contract",
    )
    if contract["schema"] != CONTRACT_SCHEMA or contract["decision"] != "PASS":
        fail("Round 9 evaluation contract is not a PASS contract")
    candidate = exact_keys(
        contract["candidate"],
        {
            "classifier_policy_version",
            "classifier_policy_sha256",
            "ruleset_version",
            "ruleset_sha256",
        },
        "Round 9 evaluation candidate",
    )
    expected_candidate = {
        "classifier_policy_version": policy["version"],
        "classifier_policy_sha256": policy["sha256"],
        "ruleset_version": ruleset["version"],
        "ruleset_sha256": ruleset["sha256"],
    }
    if candidate != expected_candidate:
        fail("evaluation contract policy/ruleset identity does not match the candidate")
    audit_contract = exact_keys(
        contract["audit_contract"],
        {
            "schema_version",
            "migration_versions",
            "quick_check",
            "wal_checkpoint_passed",
            "restart_cycle_passed",
            "raw_capture_schema_version",
            "raw_capture_only_blocked_passed",
            "raw_capture_redaction_passed",
            "decision_kinds",
            "malicious_block_requires_eligible_winner",
            "incomplete_has_no_malicious_winner",
        },
        "audit_contract",
    )
    if audit_contract != {
        "schema_version": 6,
        "migration_versions": [1, 2, 3, 4, 5, 6],
        "quick_check": "ok",
        "wal_checkpoint_passed": True,
        "restart_cycle_passed": True,
        "raw_capture_schema_version": 4,
        "raw_capture_only_blocked_passed": True,
        "raw_capture_redaction_passed": True,
        "decision_kinds": [
            "allow_clean",
            "audit_eligible_malicious_text",
            "audit_ineligible_risk",
            "block_incomplete_inspection",
            "block_malicious_text",
            "block_opaque_media",
            "block_subject_risk",
        ],
        "malicious_block_requires_eligible_winner": True,
        "incomplete_has_no_malicious_winner": True,
    }:
        fail("Round 9 audit schema v6 / Raw Capture v4 / decision-kind contract failed")
    validate_benign_section(
        contract["development_benign"],
        "development_benign",
        minimum_samples=1200,
        require_wilson=False,
    )
    validate_benign_section(
        contract["independent_benign"],
        "independent_benign",
        minimum_samples=600,
        require_wilson=True,
    )
    validate_paired_section(contract["paired_malicious"])
    validate_malicious_section(
        contract["independent_malicious"], "independent_malicious"
    )
    public = exact_keys(
        contract["public_adversarial"],
        set(PUBLIC_HOST_CONTRACT) | {"manifest_sha256"},
        "public_adversarial",
    )
    manifest_sha256 = require_hex(
        public["manifest_sha256"], "public_adversarial.manifest_sha256"
    )
    if manifest_sha256 != PUBLIC_DEVELOPMENT_MANIFEST["sha256"]:
        fail("public_adversarial manifest differs from the frozen v13 contract")
    for key, expected in PUBLIC_HOST_CONTRACT.items():
        if exact_int(public[key], f"public_adversarial.{key}") != expected:
            fail(f"public_adversarial.{key} differs from the frozen v13 contract")
    for key in ("quoted_allowed", "historical_allowed", "system_allowed", "tool_allowed"):
        if public[key] != public["scenario_payload_executions"]:
            fail(f"every executed public payload must pass the {key} carrier gate")
    route = exact_keys(
        contract["route_matrix"],
        {
            "chat_benign_upstream_delta",
            "chat_malicious_upstream_delta",
            "responses_benign_upstream_delta",
            "responses_malicious_upstream_delta",
            "benign_usage_delta",
            "malicious_usage_delta",
            "balanced_benign_blocked",
            "host_smoke_malicious_blocked",
            "host_smoke_malicious_total",
            "host_smoke_fixture_schema",
            "host_smoke_fixture_sha256",
            "stream_passed",
            "nonstream_passed",
            "balanced_incomplete_allow",
            "strict_incomplete_block",
        },
        "route_matrix",
    )
    for key in (
        "chat_benign_upstream_delta",
        "responses_benign_upstream_delta",
        "benign_usage_delta",
    ):
        exact_int(route[key], f"route_matrix.{key}", minimum=1)
    for key in (
        "chat_malicious_upstream_delta",
        "responses_malicious_upstream_delta",
        "malicious_usage_delta",
        "balanced_benign_blocked",
    ):
        if exact_int(route[key], f"route_matrix.{key}") != 0:
            fail(f"route_matrix.{key} must be zero")
    smoke_total = exact_int(
        route["host_smoke_malicious_total"],
        "route_matrix.host_smoke_malicious_total",
        minimum=1,
    )
    if exact_int(
        route["host_smoke_malicious_blocked"],
        "route_matrix.host_smoke_malicious_blocked",
        minimum=1,
    ) != smoke_total:
        fail("the counted-Mock host-smoke route matrix is incomplete")
    if route["host_smoke_fixture_schema"] != "round8-balanced-readmission/v1":
        fail("the counted-Mock host-smoke fixture schema is not the historical Round 8 matrix")
    require_hex(
        route["host_smoke_fixture_sha256"],
        "route_matrix.host_smoke_fixture_sha256",
    )
    for key in (
        "stream_passed",
        "nonstream_passed",
        "balanced_incomplete_allow",
        "strict_incomplete_block",
    ):
        if exact_bool(route[key], f"route_matrix.{key}") is not True:
            fail(f"route_matrix.{key} must be true")
    return contract


def validate_counted_mock_probe(value: dict[str, Any], commit: str, tree: str) -> dict[str, Any]:
    exact_keys(
        value,
        {"schema_version", "validation_scope", "candidate", "cpa", "mock", "safety", "execution"},
        "Round 9 counted-Mock probe",
    )
    candidate = exact_keys(
        value["candidate"],
        {"tag", "commit", "tree", "platform", "so_name", "so_sha256"},
        "Round 9 counted-Mock candidate",
    )
    if (
        value["schema_version"] != 2
        or value["validation_scope"] != "CPA_HOST_COUNTED_MOCK_ONLY"
        or candidate["tag"] != TAG
        or candidate["commit"] != commit
        or candidate["tree"] != tree
        or candidate["platform"] != "linux/amd64"
        or candidate["so_name"] != f"cyber-abuse-guard-{TAG}.so"
    ):
        fail("Round 9 counted-Mock probe is bound to another identity")
    require_hex(candidate["so_sha256"], "Round 9 probe candidate SO SHA-256")
    mock = exact_keys(
        value["mock"],
        {"contract", "source", "revision", "tag", "tree", "image_id"},
        "Round 9 counted-Mock identity",
    )
    if (
        mock["contract"] != "round9-counted-mock/v1"
        or mock["source"] != f"https://github.com/{REPOSITORY}"
        or mock["revision"] != commit
        or mock["tag"] != TAG
        or mock["tree"] != tree
    ):
        fail("Round 9 counted-Mock probe contract is invalid")
    require_hex(mock["image_id"], "Round 9 counted-Mock image ID", SHA256_DIGEST)
    cpa = exact_keys(value["cpa"], {"primary"}, "Round 9 probe CPA")
    primary = exact_keys(
        cpa["primary"],
        {"version", "commit", "image_id", "build_date", "counted_mock_validation", "host_results"},
        "Round 9 probe CPA primary",
    )
    if (
        primary["version"] != CPA_VERSION
        or primary["commit"] != CPA_COMMIT
        or primary["counted_mock_validation"] != "PASS"
    ):
        fail("Round 9 counted-Mock probe did not use the fixed CPA v7.2.109 contract")
    require_hex(primary["image_id"], "Round 9 probe CPA image ID", SHA256_DIGEST)
    safety = exact_keys(
        value["safety"],
        {
            "real_provider_contacted",
            "production_accessed",
            "unexpected_restart_count",
            "oom",
            "panic_count",
            "fatal_count",
            "plugin_error_count",
        },
        "Round 9 probe safety",
    )
    if safety != {
        "real_provider_contacted": False,
        "production_accessed": False,
        "unexpected_restart_count": 0,
        "oom": False,
        "panic_count": 0,
        "fatal_count": 0,
        "plugin_error_count": 0,
    }:
        fail("Round 9 counted-Mock probe safety assertions failed")
    execution = exact_keys(
        value["execution"],
        {"trust", "challenge", "execution_id", "started_at", "completed_at", "workflow", "phase1", "runner", "sandbox"},
        "Round 9 probe execution",
    )
    if execution["trust"] != "GITHUB_ATTESTED_ROUND9_HOST_WORKFLOW":
        fail("Round 8 evidence cannot be admitted as Round 9 counted-Mock evidence")
    workflow = exact_keys(
        execution["workflow"],
        {"repository", "path", "ref", "sha", "run_id", "run_attempt"},
        "Round 9 probe workflow",
    )
    if workflow["repository"] != REPOSITORY or workflow["path"] != HOST_WORKFLOW or workflow["ref"] != f"refs/tags/{TAG}" or workflow["sha"] != commit:
        fail("Round 9 counted-Mock signer identity is invalid")
    phase1 = exact_keys(
        execution["phase1"],
        {"workflow_path", "run_id", "run_attempt", "artifact_id", "artifact_digest"},
        "Round 9 probe Phase 1",
    )
    if phase1["workflow_path"] != RELEASE_WORKFLOW:
        fail("Round 9 counted-Mock Phase 1 identity is invalid")
    return primary


def file_report(
    path: Path, *, maximum: int, schema: str, canonical: bool = False
) -> tuple[dict[str, Any], dict[str, Any]]:
    value = read_json(path, maximum=maximum, canonical=canonical)
    if value.get("schema") != schema:
        fail(f"machine report schema is not {schema}: {path}")
    raw = path.read_bytes()
    return value, {
        "schema": schema,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def expected_report_candidate(
    commit: str, tree: str, policy: dict[str, str], ruleset: dict[str, str]
) -> dict[str, str]:
    return {
        "commit": commit,
        "tree": tree,
        "policy_version": policy["version"],
        "policy_sha256": policy["sha256"],
        "ruleset": ruleset["version"],
    }


def validate_report_candidate(
    value: Any,
    expected: dict[str, str],
    label: str,
    *,
    allow_unbound_source: bool = False,
) -> dict[str, Any]:
    candidate = exact_keys(
        value,
        {"commit", "tree", "policy_version", "policy_sha256", "ruleset"},
        f"{label}.candidate",
    )
    if allow_unbound_source:
        expected = dict(expected)
        expected["commit"] = ""
        expected["tree"] = ""
    if candidate != expected:
        fail(f"{label} candidate identity does not match the frozen candidate")
    return candidate


def validate_file_identity(value: Any, label: str) -> dict[str, Any]:
    identity = exact_keys(value, {"bytes", "sha256"}, label)
    exact_int(identity["bytes"], f"{label}.bytes", minimum=1)
    require_hex(identity["sha256"], f"{label}.sha256")
    return identity


def validate_one_shot(
    value: Any,
    *,
    corpus: str,
    expected_candidate: dict[str, str],
    manifest: dict[str, Any],
    cases: dict[str, Any],
    challenge: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
) -> dict[str, Any]:
    reservation = exact_keys(
        value,
        {
            "schema",
            "corpus",
            "candidate",
            "corpus_manifest",
            "corpus_cases",
            "workflow_run_id",
            "run_attempt",
            "challenge_sha256",
            "state",
        },
        f"{corpus}.one_shot",
    )
    if (
        reservation["schema"] != "round9-independent-one-shot-reservation/v1"
        or reservation["corpus"] != corpus
        or reservation["state"] != "reserved_before_candidate_execution"
    ):
        fail(f"{corpus} one-shot reservation identity is invalid")
    validate_report_candidate(
        reservation["candidate"], expected_candidate, f"{corpus}.one_shot"
    )
    if validate_file_identity(
        reservation["corpus_manifest"], f"{corpus}.one_shot.corpus_manifest"
    ) != manifest or validate_file_identity(
        reservation["corpus_cases"], f"{corpus}.one_shot.corpus_cases"
    ) != cases:
        fail(f"{corpus} one-shot reservation does not bind the report corpus")
    if (
        exact_int(reservation["workflow_run_id"], f"{corpus}.one_shot.workflow_run_id", minimum=1)
        != workflow_run_id
        or exact_int(reservation["run_attempt"], f"{corpus}.one_shot.run_attempt", minimum=1)
        != workflow_run_attempt
    ):
        fail(f"{corpus} one-shot reservation does not bind the Host run")
    try:
        challenge_hash = hashlib.sha256(bytes.fromhex(challenge)).hexdigest()
    except ValueError as exc:
        fail(f"invalid one-shot challenge: {exc}")
    if reservation["challenge_sha256"] != challenge_hash:
        fail(f"{corpus} one-shot reservation challenge binding is invalid")
    return reservation


def exact_int_map(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, dict) or not value:
        fail(f"{label} must be a non-empty object")
    result: dict[str, int] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            fail(f"{label} contains an invalid key")
        result[key] = exact_int(item, f"{label}.{key}")
    return result


def validate_benign_report(
    path: Path,
    *,
    profile: str,
    expected_candidate: dict[str, str],
    challenge: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    report, binding = file_report(
        path, maximum=4_194_304, schema="round9-benign-corpus-report/v1"
    )
    expected_keys = {
        "schema",
        "profile",
        "corpus",
        "corpus_manifest_bytes",
        "corpus_manifest_sha256",
        "corpus_cases_bytes",
        "corpus_cases_sha256",
        "candidate",
        "runtime",
        "platform",
        "metrics",
        "observed_benign_blocks",
        "wilson_95_upper_percent",
        "claim_boundary",
    }
    if profile == "independent":
        expected_keys.add("one_shot")
    exact_keys(report, expected_keys, f"{profile}_benign report")
    corpus = f"round9-{profile}-benign-v1"
    if report["profile"] != profile or report["corpus"] != corpus:
        fail(f"{profile} benign report identity is invalid")
    validate_report_candidate(
        report["candidate"],
        expected_candidate,
        f"{profile}_benign",
        allow_unbound_source=profile == "development",
    )
    if report["runtime"] != "go1.26.4" or report["platform"] != "linux/amd64":
        fail(f"{profile} benign report requires Go 1.26.4 on linux/amd64")
    manifest = {
        "bytes": exact_int(
            report["corpus_manifest_bytes"],
            f"{profile}_benign.corpus_manifest_bytes",
            minimum=1,
        ),
        "sha256": require_hex(
            report["corpus_manifest_sha256"],
            f"{profile}_benign.corpus_manifest_sha256",
        ),
    }
    cases = {
        "bytes": exact_int(
            report["corpus_cases_bytes"],
            f"{profile}_benign.corpus_cases_bytes",
            minimum=1,
        ),
        "sha256": require_hex(
            report["corpus_cases_sha256"],
            f"{profile}_benign.corpus_cases_sha256",
        ),
    }
    if profile == "independent":
        validate_one_shot(
            report["one_shot"],
            corpus=corpus,
            expected_candidate=expected_candidate,
            manifest=manifest,
            cases=cases,
            challenge=challenge,
            workflow_run_id=workflow_run_id,
            workflow_run_attempt=workflow_run_attempt,
        )
    metrics = exact_keys(
        report["metrics"],
        {
            "schema",
            "unique_semantic_samples",
            "serialized_route_executions",
            "blocked_executions",
            "audit_executions",
            "allow_executions",
            "category_counts",
            "language_counts",
            "protocol_counts",
            "stream_counts",
            "carrier_counts",
            "mode_counts",
        },
        f"{profile}_benign.metrics",
    )
    if metrics["schema"] != "round9-route-executions/v1":
        fail(f"{profile} benign route schema is invalid")
    minimum = 1200 if profile == "development" else 600
    unique = exact_int(
        metrics["unique_semantic_samples"],
        f"{profile}_benign.metrics.unique_semantic_samples",
        minimum=minimum,
    )
    routes = exact_int(
        metrics["serialized_route_executions"],
        f"{profile}_benign.metrics.serialized_route_executions",
        minimum=minimum * 6,
    )
    if routes != unique * 6:
        fail(f"{profile} benign route executions must remain six per semantic request")
    blocked = exact_int(metrics["blocked_executions"], f"{profile}_benign.metrics.blocked_executions")
    if blocked != 0 or exact_int(report["observed_benign_blocks"], f"{profile}_benign.observed_benign_blocks") != 0:
        fail(f"{profile}_benign contains a normal request block")
    audit = exact_int(metrics["audit_executions"], f"{profile}_benign.metrics.audit_executions")
    allowed = exact_int(metrics["allow_executions"], f"{profile}_benign.metrics.allow_executions")
    if audit + allowed != routes:
        fail(f"{profile} benign route accounting is contradictory")
    categories = exact_int_map(metrics["category_counts"], f"{profile}_benign.metrics.category_counts")
    languages = exact_int_map(metrics["language_counts"], f"{profile}_benign.metrics.language_counts")
    protocols = exact_int_map(metrics["protocol_counts"], f"{profile}_benign.metrics.protocol_counts")
    streams = exact_int_map(metrics["stream_counts"], f"{profile}_benign.metrics.stream_counts")
    carriers = exact_int_map(metrics["carrier_counts"], f"{profile}_benign.metrics.carrier_counts")
    modes = exact_int_map(metrics["mode_counts"], f"{profile}_benign.metrics.mode_counts")
    if (
        len(categories) != 15
        or sum(categories.values()) != unique
        or set(languages) != {"en", "zh"}
        or sum(languages.values()) != unique
        or sum(protocols.values()) != routes
        or set(streams) != {"false", "true"}
        or sum(streams.values()) != routes
        or min(streams.values()) < unique * 2
        or sum(carriers.values()) != routes
        or sum(modes.values()) != routes
    ):
        fail(f"{profile} benign distribution accounting is invalid")
    summary = {
        "corpus_sha256": cases["sha256"],
        "ground_truth_sha256": manifest["sha256"],
        "unique_semantic_samples": unique,
        "serialized_route_executions": routes,
        "blocked": 0,
        "hard_policy_blocked": 0,
    }
    if profile == "independent":
        summary["wilson_upper_bound_ppm"] = round(
            1_000_000 * 1.96**2 / (unique + 1.96**2)
        )
    return summary, binding


def wilson_interval(successes: int, total: int) -> tuple[float, float]:
    if total <= 0 or successes < 0 or successes > total:
        fail("Wilson interval inputs are invalid")
    z = 1.959963984540054
    probability = successes / total
    z2 = z * z
    denominator = 1 + z2 / total
    center = probability + z2 / (2 * total)
    margin = z * math.sqrt(
        probability * (1 - probability) / total + z2 / (4 * total * total)
    )
    return (center - margin) / denominator, (center + margin) / denominator


def validate_malicious_report(
    path: Path,
    *,
    expected_candidate: dict[str, str],
    challenge: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    report, binding = file_report(
        path, maximum=4_194_304, schema="round9-independent-malicious-report/v1"
    )
    exact_keys(
        report,
        {
            "schema",
            "corpus",
            "corpus_manifest",
            "corpus_cases",
            "candidate",
            "one_shot",
            "runtime",
            "platform",
            "metrics",
            "recall_percent",
            "wilson_95_lower_percent",
            "wilson_95_upper_percent",
            "claim_boundary",
        },
        "independent_malicious report",
    )
    corpus = "round9-independent-malicious-v1"
    if report["corpus"] != corpus or report["runtime"] != "go1.26.4" or report["platform"] != "linux/amd64":
        fail("independent malicious report identity is invalid")
    validate_report_candidate(report["candidate"], expected_candidate, "independent_malicious")
    manifest = validate_file_identity(report["corpus_manifest"], "independent_malicious.corpus_manifest")
    cases = validate_file_identity(report["corpus_cases"], "independent_malicious.corpus_cases")
    validate_one_shot(
        report["one_shot"],
        corpus=corpus,
        expected_candidate=expected_candidate,
        manifest=manifest,
        cases=cases,
        challenge=challenge,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
    )
    metrics = exact_keys(
        report["metrics"],
        {
            "schema",
            "unique_semantic_samples",
            "semantic_blocked",
            "serialized_route_executions",
            "passed_route_executions",
            "category_counts",
            "language_counts",
            "protocol_counts",
            "stream_counts",
            "mode_counts",
            "per_category",
            "failures",
        },
        "independent_malicious.metrics",
    )
    if metrics["schema"] != "round9-malicious-route-executions/v1":
        fail("independent malicious route schema is invalid")
    samples = exact_int(metrics["unique_semantic_samples"], "independent_malicious.samples", minimum=90)
    blocked = exact_int(metrics["semantic_blocked"], "independent_malicious.blocked")
    routes = exact_int(metrics["serialized_route_executions"], "independent_malicious.routes", minimum=samples * 8)
    passed_routes = exact_int(metrics["passed_route_executions"], "independent_malicious.passed_routes")
    if routes != samples * 8 or passed_routes != routes or blocked > samples or blocked * 10000 // samples < 9500:
        fail("independent malicious report does not meet the frozen recall/route contract")
    if not isinstance(metrics["failures"], list) or metrics["failures"]:
        fail("independent malicious report contains failed semantic or route executions")
    categories = exact_int_map(metrics["category_counts"], "independent_malicious.category_counts")
    languages = exact_int_map(metrics["language_counts"], "independent_malicious.language_counts")
    protocols = exact_int_map(metrics["protocol_counts"], "independent_malicious.protocol_counts")
    streams = exact_int_map(metrics["stream_counts"], "independent_malicious.stream_counts")
    modes = exact_int_map(metrics["mode_counts"], "independent_malicious.mode_counts")
    per_category = metrics["per_category"]
    if (
        len(categories) != 9
        or sum(categories.values()) != samples
        or set(languages) != {"en", "zh"}
        or sum(languages.values()) != samples
        or sum(protocols.values()) != routes
        or streams != {"false": samples * 4, "true": samples * 4}
        or sum(modes.values()) != routes
        or not isinstance(per_category, dict)
        or set(per_category) != set(categories)
    ):
        fail("independent malicious distribution accounting is invalid")
    for category, value in per_category.items():
        item = exact_keys(
            value,
            {
                "semantic_samples",
                "semantic_blocked",
                "route_executions",
                "passed_route_executions",
                "recall_percent",
                "wilson_95_lower_percent",
                "wilson_95_upper_percent",
            },
            f"independent_malicious.per_category.{category}",
        )
        category_samples = exact_int(item["semantic_samples"], f"{category}.semantic_samples", minimum=1)
        category_blocked = exact_int(item["semantic_blocked"], f"{category}.semantic_blocked")
        category_routes = exact_int(item["route_executions"], f"{category}.route_executions", minimum=8)
        if (
            category_samples != categories[category]
            or category_routes != category_samples * 8
            or exact_int(item["passed_route_executions"], f"{category}.passed_route_executions") != category_routes
            or category_blocked > category_samples
            or category_blocked * 10000 // category_samples < 9500
        ):
            fail(f"independent malicious category recall failed: {category}")
    lower, _ = wilson_interval(blocked, samples)
    return {
        "corpus_sha256": cases["sha256"],
        "ground_truth_sha256": manifest["sha256"],
        "samples": samples,
        "eligible_samples": samples,
        "blocked": blocked,
        "recall_basis_points": blocked * 10000 // samples,
        "wilson_lower_bound_basis_points": round(lower * 10000),
    }, binding


def validate_paired_report(
    path: Path,
    log_path: Path,
    expected_candidate: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    report, binding = file_report(
        path,
        maximum=4_194_304,
        schema="round9-development-paired-malicious-machine-report/v1",
        canonical=True,
    )
    exact_keys(
        report,
        {
            "schema",
            "source_report_schema",
            "corpus",
            "corpus_manifest_version",
            "corpus_manifest",
            "corpus_cases",
            "corpus_label_audit",
            "benign_corpus_manifest",
            "benign_corpus_cases",
            "candidate",
            "runtime",
            "platform",
            "metrics",
            "producer_log",
            "claim_boundary",
        },
        "paired malicious machine report",
    )
    validate_report_candidate(report["candidate"], expected_candidate, "paired_malicious")
    validate_log_binding(report, log_path, "paired_malicious")
    schema = exact_string(report["source_report_schema"], "paired source report schema")
    corpus = exact_string(report["corpus"], "paired corpus name")
    schema_match = PAIRED_SOURCE_SCHEMA.fullmatch(schema)
    corpus_match = PAIRED_CORPUS.fullmatch(corpus)
    if (
        schema_match is None
        or corpus_match is None
        or int(schema_match.group("version")) < 3
        or int(corpus_match.group("version")) < 3
        or schema_match.group("version") != corpus_match.group("version")
        or report["runtime"] != "go1.26.4"
        or report["platform"] != "linux/amd64"
    ):
        fail("paired malicious machine report identity is invalid")
    manifest = validate_file_identity(report["corpus_manifest"], "paired.corpus_manifest")
    cases = validate_file_identity(report["corpus_cases"], "paired.corpus_cases")
    if exact_int(
        report["corpus_manifest_version"], "paired.corpus_manifest_version"
    ) != 2:
        fail("paired malicious machine report must bind manifest version 2")
    label_audit = validate_file_identity(
        report["corpus_label_audit"], "paired.corpus_label_audit"
    )
    if label_audit["bytes"] < 512:
        fail("paired malicious label-audit binding is below the reviewed minimum size")
    benign_manifest = validate_file_identity(
        report["benign_corpus_manifest"], "paired.benign_corpus_manifest"
    )
    benign_cases = validate_file_identity(
        report["benign_corpus_cases"], "paired.benign_corpus_cases"
    )
    metrics = exact_keys(
        report["metrics"],
        {
            "unique_semantic_samples",
            "semantic_blocked",
            "serialized_route_executions",
            "passed_route_executions",
            "recall_basis_points",
            "wilson_lower_bound_basis_points",
            "wilson_upper_bound_basis_points",
            "per_category",
        },
        "paired malicious machine metrics",
    )
    section = {
        "corpus_name": corpus,
        "source_report_schema": schema,
        "corpus_manifest_version": 2,
        "corpus_manifest_sha256": manifest["sha256"],
        "corpus_cases_sha256": cases["sha256"],
        "label_audit": label_audit,
        "benign_corpus_manifest_sha256": benign_manifest["sha256"],
        "benign_corpus_cases_sha256": benign_cases["sha256"],
        "samples": metrics["unique_semantic_samples"],
        "blocked": metrics["semantic_blocked"],
        "serialized_route_executions": metrics["serialized_route_executions"],
        "passed_route_executions": metrics["passed_route_executions"],
        "recall_basis_points": metrics["recall_basis_points"],
        "wilson_lower_bound_basis_points": metrics["wilson_lower_bound_basis_points"],
        "wilson_upper_bound_basis_points": metrics["wilson_upper_bound_basis_points"],
        "per_category": metrics["per_category"],
    }
    validate_paired_section(section)
    return section, binding


def validate_log_binding(report: dict[str, Any], log_path: Path, label: str) -> None:
    binding = exact_keys(report["producer_log"], {"bytes", "sha256"}, f"{label}.producer_log")
    raw = log_path.read_bytes() if log_path.is_file() and not log_path.is_symlink() else b""
    if (
        not raw
        or len(raw) != exact_int(binding["bytes"], f"{label}.producer_log.bytes", minimum=1)
        or hashlib.sha256(raw).hexdigest() != require_hex(binding["sha256"], f"{label}.producer_log.sha256")
    ):
        fail(f"{label} producer log is missing or does not match its report")


def validate_public_report(
    path: Path,
    log_path: Path,
    expected_candidate: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    report, binding = file_report(
        path,
        maximum=262144,
        schema=PUBLIC_DEVELOPMENT_REPORT_SCHEMA,
        canonical=True,
    )
    exact_keys(
        report,
        {"schema", "candidate", "manifest", "producer_log", "metrics", "claim_boundary"},
        "public adversarial report",
    )
    validate_report_candidate(report["candidate"], expected_candidate, "public_adversarial")
    manifest = validate_file_identity(report["manifest"], "public_adversarial.manifest")
    if manifest != PUBLIC_DEVELOPMENT_MANIFEST:
        fail("public adversarial report does not bind the frozen v13 manifest")
    validate_log_binding(report, log_path, "public_adversarial")
    metrics = exact_keys(
        report["metrics"],
        {
            "payload_records",
            "formal_unique_payloads",
            "candidate_carriers",
            "candidate_executions",
            "not_provided",
            "scenario_payload_executions",
            "serialized_route_executions",
            "direct_blocked",
            "direct_allowed",
            "quoted_blocked",
            "historical_blocked",
            "system_blocked",
            "tool_blocked",
        },
        "public_adversarial.metrics",
    )
    if metrics != PUBLIC_DEVELOPMENT_METRICS:
        fail("public adversarial machine report differs from the frozen v13 contract")
    return {
        "manifest_sha256": manifest["sha256"],
        **PUBLIC_HOST_CONTRACT,
    }, binding


def validate_audit_report(
    path: Path,
    log_path: Path,
    expected_candidate: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    report, binding = file_report(
        path,
        maximum=262144,
        schema="round9-audit-contract-report/v1",
        canonical=True,
    )
    exact_keys(
        report,
        {"schema", "candidate", "producer_log", "contract", "claim_boundary"},
        "audit contract report",
    )
    validate_report_candidate(report["candidate"], expected_candidate, "audit_contract")
    validate_log_binding(report, log_path, "audit_contract")
    result = exact_keys(
        report["contract"],
        {
            "decision_kinds",
            "malicious_block_requires_eligible_winner",
            "incomplete_has_no_malicious_winner",
        },
        "audit_contract.contract",
    )
    expected_kinds = [
        "allow_clean",
        "audit_eligible_malicious_text",
        "audit_ineligible_risk",
        "block_incomplete_inspection",
        "block_malicious_text",
        "block_opaque_media",
        "block_subject_risk",
    ]
    if result != {
        "decision_kinds": expected_kinds,
        "malicious_block_requires_eligible_winner": True,
        "incomplete_has_no_malicious_winner": True,
    }:
        fail("audit decision-kind/eligibility machine contract failed")
    return result, binding


def host_smoke_corpus_identity(path: Path) -> dict[str, Any]:
    value = read_json(path, maximum=262144, canonical=False)
    if value.get("schema") != "round8-balanced-readmission/v1" or not isinstance(value.get("pairs"), list) or len(value["pairs"]) != 42:
        fail("counted-Mock host-smoke fixture identity is invalid")
    raw = path.read_bytes()
    return {
        "schema": "round8-balanced-readmission/v1",
        "samples": 42,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def derive_contract_from_machine_reports(
    args: argparse.Namespace,
    *,
    policy: dict[str, str],
    ruleset: dict[str, str],
    primary: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    expected_candidate = expected_report_candidate(args.commit, args.tree, policy, ruleset)
    development, development_binding = validate_benign_report(
        args.development_benign_report,
        profile="development",
        expected_candidate=expected_candidate,
        challenge=args.challenge,
        workflow_run_id=args.workflow_run_id,
        workflow_run_attempt=args.workflow_run_attempt,
    )
    independent, independent_binding = validate_benign_report(
        args.independent_benign_report,
        profile="independent",
        expected_candidate=expected_candidate,
        challenge=args.challenge,
        workflow_run_id=args.workflow_run_id,
        workflow_run_attempt=args.workflow_run_attempt,
    )
    malicious, malicious_binding = validate_malicious_report(
        args.independent_malicious_report,
        expected_candidate=expected_candidate,
        challenge=args.challenge,
        workflow_run_id=args.workflow_run_id,
        workflow_run_attempt=args.workflow_run_attempt,
    )
    paired, paired_binding = validate_paired_report(
        args.paired_malicious_report,
        args.paired_malicious_log,
        expected_candidate,
    )
    if (
        paired["benign_corpus_manifest_sha256"] != development["ground_truth_sha256"]
        or paired["benign_corpus_cases_sha256"] != development["corpus_sha256"]
    ):
        fail("paired malicious report does not bind the development benign baseline")
    public, public_binding = validate_public_report(
        args.public_adversarial_report,
        args.public_adversarial_log,
        expected_candidate,
    )
    audit_machine, audit_binding = validate_audit_report(
        args.audit_report, args.audit_log, expected_candidate
    )
    host_smoke_identity = host_smoke_corpus_identity(args.host_smoke_corpus)
    host_results = exact_keys(
        primary["host_results"],
        {"network_binding", "protocol_requests", "matrix", "transports", "modes", "policy_outcomes", "database", "raw_capture", "lifecycle"},
        "counted-Mock host_results",
    )
    network_binding = exact_keys(
        host_results["network_binding"],
        {"host_ip", "host_port", "container_port"},
        "counted-Mock CPA network binding",
    )
    if network_binding != {
        "host_ip": CPA_HOST_IP,
        "host_port": CPA_HOST_PORT,
        "container_port": CPA_CONTAINER_PORT,
    }:
        fail("counted-Mock CPA must listen only on 127.0.0.1:18394 -> 8317")
    matrix = exact_keys(
        host_results["matrix"],
        {
            "benign_total",
            "benign_passed",
            "host_smoke_malicious_total",
            "host_smoke_malicious_blocked",
        },
        "counted-Mock matrix",
    )
    host_smoke_total = exact_int(
        matrix["host_smoke_malicious_total"],
        "host_smoke_malicious_total",
        minimum=1,
    )
    host_smoke_blocked = exact_int(
        matrix["host_smoke_malicious_blocked"], "host_smoke_malicious_blocked"
    )
    if (
        host_smoke_total != host_smoke_identity["samples"]
        or host_smoke_blocked > host_smoke_total
        or host_smoke_blocked * 10000 // host_smoke_total < 9500
    ):
        fail("counted-Mock host-smoke matrix failed")
    database = exact_keys(
        host_results["database"],
        {"quick_check", "schema_version", "migration_versions", "wal_checkpoint_passed"},
        "counted-Mock database",
    )
    raw_capture = exact_keys(
        host_results["raw_capture"],
        {"only_blocked_passed", "ttl_dedup_passed", "schema_v4_redaction_metadata_passed", "purge_wal_passed"},
        "counted-Mock raw_capture",
    )
    lifecycle = exact_keys(
        host_results["lifecycle"],
        {"restart_cycle_passed", "unexpected_restart_count", "oom", "panic_count", "fatal_count", "plugin_error_count"},
        "counted-Mock lifecycle",
    )
    audit_contract = {
        "schema_version": database["schema_version"],
        "migration_versions": database["migration_versions"],
        "quick_check": database["quick_check"],
        "wal_checkpoint_passed": database["wal_checkpoint_passed"],
        "restart_cycle_passed": lifecycle["restart_cycle_passed"],
        "raw_capture_schema_version": 4,
        "raw_capture_only_blocked_passed": raw_capture["only_blocked_passed"],
        "raw_capture_redaction_passed": raw_capture["schema_v4_redaction_metadata_passed"],
        **audit_machine,
    }
    protocol = host_results["protocol_requests"]
    transport = host_results["transports"]
    outcomes = host_results["policy_outcomes"]
    route_matrix = {
        "chat_benign_upstream_delta": protocol["chat_benign_upstream"],
        "chat_malicious_upstream_delta": protocol["chat_malicious_upstream"],
        "responses_benign_upstream_delta": protocol["responses_benign_upstream"],
        "responses_malicious_upstream_delta": protocol["responses_malicious_upstream"],
        "benign_usage_delta": outcomes["usage_queue_allow_delta"],
        "malicious_usage_delta": 0 if outcomes["usage_queue_blocked_zero"] is True else 1,
        "balanced_benign_blocked": matrix["benign_total"] - matrix["benign_passed"],
        "host_smoke_malicious_blocked": host_smoke_blocked,
        "host_smoke_malicious_total": host_smoke_total,
        "host_smoke_fixture_schema": host_smoke_identity["schema"],
        "host_smoke_fixture_sha256": host_smoke_identity["sha256"],
        "stream_passed": transport["stream_passed"],
        "nonstream_passed": transport["nonstream_passed"],
        "balanced_incomplete_allow": outcomes["balanced_incomplete_allow"],
        "strict_incomplete_block": outcomes["strict_incomplete_block"],
    }
    contract = {
        "schema": CONTRACT_SCHEMA,
        "decision": "PASS",
        "candidate": {
            "classifier_policy_version": policy["version"],
            "classifier_policy_sha256": policy["sha256"],
            "ruleset_version": ruleset["version"],
            "ruleset_sha256": ruleset["sha256"],
        },
        "audit_contract": audit_contract,
        "development_benign": development,
        "independent_benign": independent,
        "paired_malicious": paired,
        "independent_malicious": malicious,
        "public_adversarial": public,
        "route_matrix": route_matrix,
    }
    validate_contract(contract, policy, ruleset)
    return contract, {
        "development_benign": development_binding,
        "independent_benign": independent_binding,
        "paired_malicious": paired_binding,
        "independent_malicious": malicious_binding,
        "public_adversarial": public_binding,
        "audit_contract": audit_binding,
    }


def build_evidence(args: argparse.Namespace) -> dict[str, Any]:
    commit = require_hex(args.commit, "commit", HEX40)
    tree = require_hex(args.tree, "tree", HEX40)
    if args.tag != TAG:
        fail(f"Round 9 Host evidence tag must be {TAG}")
    policy = policy_identity(args.policy_source)
    ruleset = ruleset_identity(args.ruleset_manifest, args.ruleset_sidecar)
    probe = read_json(args.probe_evidence, maximum=32768)
    probe_sha = require_sidecar(args.probe_sidecar, args.probe_evidence)
    primary = validate_counted_mock_probe(probe, commit, tree)
    if args.candidate_so.is_symlink() or not args.candidate_so.is_file():
        fail("candidate SO must be a regular file")
    so_sha = hashlib.sha256(args.candidate_so.read_bytes()).hexdigest()
    if probe["candidate"]["so_sha256"] != so_sha:
        fail("Round 9 counted-Mock probe SO does not match the frozen candidate")
    challenge = require_hex(args.challenge, "challenge")
    if args.workflow_path != HOST_WORKFLOW:
        fail("Round 9 Host signer path is not exact")
    if args.workflow_ref != f"refs/tags/{TAG}":
        fail("Round 9 Host signer ref is not exact")
    if args.release_workflow_path != RELEASE_WORKFLOW:
        fail("Round 9 Phase 1 workflow path is not exact")
    for label in (
        "workflow_run_id",
        "workflow_run_attempt",
        "phase1_run_id",
        "phase1_run_attempt",
        "phase1_artifact_id",
    ):
        exact_int(getattr(args, label), label, minimum=1)
    require_hex(args.phase1_artifact_digest, "phase1 artifact digest", SHA256_DIGEST)
    execution = exact_keys(probe["execution"], {"trust", "challenge", "execution_id", "started_at", "completed_at", "workflow", "phase1", "runner", "sandbox"}, "Round 9 probe execution")
    probe_workflow = execution["workflow"]
    probe_phase1 = execution["phase1"]
    if (
        execution["challenge"] != challenge
        or probe_workflow["run_id"] != args.workflow_run_id
        or probe_workflow["run_attempt"] != args.workflow_run_attempt
        or probe_phase1["run_id"] != args.phase1_run_id
        or probe_phase1["run_attempt"] != args.phase1_run_attempt
        or probe_phase1["artifact_id"] != args.phase1_artifact_id
        or probe_phase1["artifact_digest"] != args.phase1_artifact_digest
    ):
        fail("Round 9 counted-Mock probe execution binding does not match dispatch")
    runner = exact_keys(
        execution["runner"], {"name", "environment", "os", "arch"}, "Round 9 probe runner"
    )
    if runner["environment"] != "self-hosted" or runner["os"] != "Linux" or runner["arch"] != "X64":
        fail("Round 9 Host evidence requires a self-hosted Linux x64 runner")
    sandbox = exact_keys(
        execution["sandbox"],
        {"sandbox_id", "daemon_id", "daemon_label", "production_label", "probe_image_id", "locality_challenge"},
        "Round 9 probe sandbox",
    )
    if sandbox["production_label"] != "io.cyber-abuse-guard.production=false" or sandbox["locality_challenge"] != "PASS":
        fail("Round 9 Host sandbox is not isolated")
    contract, machine_reports = derive_contract_from_machine_reports(
        args, policy=policy, ruleset=ruleset, primary=primary
    )
    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "validation_scope": VALIDATION_SCOPE,
        "candidate": {
            "tag": TAG,
            "commit": commit,
            "tree": tree,
            "platform": "linux/amd64",
            "so_name": f"cyber-abuse-guard-{TAG}.so",
            "so_sha256": so_sha,
            "classifier": policy,
            "ruleset": ruleset,
        },
        "cpa": {
            "primary": {
                "version": CPA_VERSION,
                "commit": CPA_COMMIT,
                "image_id": primary["image_id"],
                "build_date": primary["build_date"],
                "counted_mock_validation": "PASS",
                "host_results": primary["host_results"],
            }
        },
        "corpus": {
            key: contract[key]
            for key in (
                "development_benign",
                "independent_benign",
                "paired_malicious",
                "independent_malicious",
                "public_adversarial",
                "route_matrix",
            )
        },
        "audit_contract": contract["audit_contract"],
        "machine_reports": machine_reports,
        "counted_mock_probe": {
            "contract": "round9-counted-mock/v1",
            "evidence_sha256": probe_sha,
            "purpose": "bounded-linux-counted-mock-execution",
        },
        "safety": probe["safety"],
        "execution": {
            "trust": "GITHUB_ATTESTED_ROUND9_HOST_WORKFLOW",
            "challenge": challenge,
            "execution_id": execution["execution_id"],
            "started_at": execution["started_at"],
            "completed_at": execution["completed_at"],
            "workflow": {
                "repository": REPOSITORY,
                "path": HOST_WORKFLOW,
                "ref": f"refs/tags/{TAG}",
                "sha": commit,
                "run_id": args.workflow_run_id,
                "run_attempt": args.workflow_run_attempt,
            },
            "phase1": {
                "workflow_path": RELEASE_WORKFLOW,
                "run_id": args.phase1_run_id,
                "run_attempt": args.phase1_run_attempt,
                "artifact_id": args.phase1_artifact_id,
                "artifact_digest": args.phase1_artifact_digest,
            },
            "runner": runner,
            "sandbox": sandbox,
        },
    }


def validate_machine_report_bindings(value: Any) -> None:
    reports = exact_keys(
        value,
        {
            "development_benign",
            "independent_benign",
            "paired_malicious",
            "independent_malicious",
            "public_adversarial",
            "audit_contract",
        },
        "machine_reports",
    )
    expected_schemas = {
        "development_benign": "round9-benign-corpus-report/v1",
        "independent_benign": "round9-benign-corpus-report/v1",
        "paired_malicious": "round9-development-paired-malicious-machine-report/v1",
        "independent_malicious": "round9-independent-malicious-report/v1",
        "public_adversarial": PUBLIC_DEVELOPMENT_REPORT_SCHEMA,
        "audit_contract": "round9-audit-contract-report/v1",
    }
    for name, schema in expected_schemas.items():
        binding = exact_keys(
            reports[name], {"schema", "bytes", "sha256"}, f"machine_reports.{name}"
        )
        if binding["schema"] != schema:
            fail(f"machine_reports.{name} schema identity is invalid")
        exact_int(binding["bytes"], f"machine_reports.{name}.bytes", minimum=1)
        require_hex(binding["sha256"], f"machine_reports.{name}.sha256")


def validate_evidence(value: dict[str, Any], args: argparse.Namespace) -> None:
    exact_keys(
        value,
        {
            "schema",
            "schema_version",
            "validation_scope",
            "candidate",
            "cpa",
            "corpus",
            "audit_contract",
            "machine_reports",
            "counted_mock_probe",
            "safety",
            "execution",
        },
        "Round 9 Host evidence",
    )
    if value["schema"] != SCHEMA or value["schema_version"] != 1:
        fail("Round 9 Host evidence schema identity is invalid")
    if value["validation_scope"] != VALIDATION_SCOPE:
        fail("Round 9 Host evidence scope is invalid")
    candidate = exact_keys(
        value["candidate"],
        {"tag", "commit", "tree", "platform", "so_name", "so_sha256", "classifier", "ruleset"},
        "Round 9 candidate",
    )
    if args.tag is not None and candidate["tag"] != args.tag:
        fail("Round 9 Host evidence tag mismatch")
    if args.commit is not None and candidate["commit"] != args.commit:
        fail("Round 9 Host evidence commit mismatch")
    if args.tree is not None and candidate["tree"] != args.tree:
        fail("Round 9 Host evidence tree mismatch")
    if candidate["tag"] != TAG or candidate["platform"] != "linux/amd64" or candidate["so_name"] != f"cyber-abuse-guard-{TAG}.so":
        fail("Round 9 candidate fixed identity is invalid")
    require_hex(candidate["commit"], "candidate.commit", HEX40)
    require_hex(candidate["tree"], "candidate.tree", HEX40)
    require_hex(candidate["so_sha256"], "candidate.so_sha256")
    policy = exact_keys(candidate["classifier"], {"version", "sha256"}, "candidate.classifier")
    ruleset = exact_keys(candidate["ruleset"], {"version", "sha256"}, "candidate.ruleset")
    require_hex(policy["sha256"], "candidate.classifier.sha256")
    require_hex(ruleset["sha256"], "candidate.ruleset.sha256")
    if args.policy_source is not None and policy_identity(args.policy_source) != policy:
        fail("Round 9 Host evidence classifier identity does not match source")
    if args.ruleset_manifest is not None:
        if args.ruleset_sidecar is None:
            fail("ruleset sidecar is required with a ruleset manifest")
        if ruleset_identity(args.ruleset_manifest, args.ruleset_sidecar) != ruleset:
            fail("Round 9 Host evidence ruleset identity does not match artifacts")
    contract = {
        "schema": CONTRACT_SCHEMA,
        "decision": "PASS",
        "candidate": {
            "classifier_policy_version": policy["version"],
            "classifier_policy_sha256": policy["sha256"],
            "ruleset_version": ruleset["version"],
            "ruleset_sha256": ruleset["sha256"],
        },
        "audit_contract": value["audit_contract"],
        **value["corpus"],
    }
    validate_contract(contract, policy, ruleset)
    validate_machine_report_bindings(value["machine_reports"])
    cpa = exact_keys(value["cpa"], {"primary"}, "Round 9 CPA")
    primary = exact_keys(
        cpa["primary"],
        {"version", "commit", "image_id", "build_date", "counted_mock_validation", "host_results"},
        "Round 9 CPA primary",
    )
    if primary["version"] != CPA_VERSION or primary["commit"] != CPA_COMMIT or primary["counted_mock_validation"] != "PASS":
        fail("Round 9 CPA v7.2.109 identity or counted-Mock result is invalid")
    require_hex(primary["image_id"], "Round 9 CPA image ID", SHA256_DIGEST)
    probe = exact_keys(value["counted_mock_probe"], {"contract", "evidence_sha256", "purpose"}, "counted_mock_probe")
    if probe["contract"] != "round9-counted-mock/v1" or probe["purpose"] != "bounded-linux-counted-mock-execution":
        fail("Round 9 counted-Mock probe identity is invalid")
    require_hex(probe["evidence_sha256"], "counted_mock_probe.evidence_sha256")
    safety = value["safety"]
    if safety != {
        "real_provider_contacted": False,
        "production_accessed": False,
        "unexpected_restart_count": 0,
        "oom": False,
        "panic_count": 0,
        "fatal_count": 0,
        "plugin_error_count": 0,
    }:
        fail("Round 9 Host safety assertions failed")
    execution = exact_keys(
        value["execution"],
        {"trust", "challenge", "execution_id", "started_at", "completed_at", "workflow", "phase1", "runner", "sandbox"},
        "Round 9 execution",
    )
    if execution["trust"] != "GITHUB_ATTESTED_ROUND9_HOST_WORKFLOW":
        fail("Round 9 Host trust identity is invalid")
    require_hex(execution["challenge"], "execution.challenge")
    if args.challenge is not None and execution["challenge"] != args.challenge:
        fail("Round 9 Host challenge mismatch")
    workflow = exact_keys(
        execution["workflow"],
        {"repository", "path", "ref", "sha", "run_id", "run_attempt"},
        "Round 9 workflow binding",
    )
    if workflow["repository"] != REPOSITORY or workflow["path"] != HOST_WORKFLOW or workflow["ref"] != f"refs/tags/{TAG}" or workflow["sha"] != candidate["commit"]:
        fail("Round 9 Host signer workflow binding is invalid")
    exact_int(workflow["run_id"], "workflow.run_id", minimum=1)
    exact_int(workflow["run_attempt"], "workflow.run_attempt", minimum=1)
    if args.workflow_run_id is not None and workflow["run_id"] != args.workflow_run_id:
        fail("Round 9 Host run ID mismatch")
    if args.workflow_run_attempt is not None and workflow["run_attempt"] != args.workflow_run_attempt:
        fail("Round 9 Host run attempt mismatch")
    phase1 = exact_keys(
        execution["phase1"],
        {"workflow_path", "run_id", "run_attempt", "artifact_id", "artifact_digest"},
        "Round 9 Phase 1 binding",
    )
    if phase1["workflow_path"] != RELEASE_WORKFLOW:
        fail("Round 9 Phase 1 workflow binding is invalid")
    for key in ("run_id", "run_attempt", "artifact_id"):
        exact_int(phase1[key], f"phase1.{key}", minimum=1)
    require_hex(phase1["artifact_digest"], "phase1.artifact_digest", SHA256_DIGEST)
    for name, expected in (
        ("run_id", args.phase1_run_id),
        ("run_attempt", args.phase1_run_attempt),
        ("artifact_id", args.phase1_artifact_id),
        ("artifact_digest", args.phase1_artifact_digest),
    ):
        if expected is not None and phase1[name] != expected:
            fail(f"Round 9 Phase 1 {name} mismatch")
    runner = exact_keys(execution["runner"], {"name", "environment", "os", "arch"}, "Round 9 runner")
    if runner["environment"] != "self-hosted" or runner["os"] != "Linux" or runner["arch"] != "X64":
        fail("Round 9 runner is not self-hosted Linux x64")
    exact_keys(
        execution["sandbox"],
        {"sandbox_id", "daemon_id", "daemon_label", "production_label", "probe_image_id", "locality_challenge"},
        "Round 9 sandbox",
    )
    if args.candidate_so is not None:
        if args.candidate_so.is_symlink() or not args.candidate_so.is_file():
            fail("candidate SO must be a regular file")
        if hashlib.sha256(args.candidate_so.read_bytes()).hexdigest() != candidate["so_sha256"]:
            fail("Round 9 Host evidence does not bind the candidate SO")


def write_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload)


def assemble(args: argparse.Namespace) -> None:
    evidence = build_evidence(args)
    payload = canonical_bytes(evidence)
    if len(payload) > 65536:
        fail("Round 9 Host evidence exceeds the reviewed size bound")
    write_exclusive(args.output, payload)
    digest = hashlib.sha256(payload).hexdigest()
    write_exclusive(args.sidecar, f"{digest}  {args.output.name}\n".encode())


def validate(args: argparse.Namespace) -> None:
    evidence = read_json(args.evidence, maximum=65536)
    validate_evidence(evidence, args)
    if args.sidecar is not None:
        require_sidecar(args.sidecar, args.evidence)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    build = commands.add_parser("assemble")
    for name, kind in (
        ("probe-evidence", Path),
        ("probe-sidecar", Path),
        ("development-benign-report", Path),
        ("independent-benign-report", Path),
        ("paired-malicious-report", Path),
        ("paired-malicious-log", Path),
        ("independent-malicious-report", Path),
        ("public-adversarial-report", Path),
        ("public-adversarial-log", Path),
        ("audit-report", Path),
        ("audit-log", Path),
        ("host-smoke-corpus", Path),
        ("candidate-so", Path),
        ("policy-source", Path),
        ("ruleset-manifest", Path),
        ("ruleset-sidecar", Path),
        ("output", Path),
        ("sidecar", Path),
        ("tag", str),
        ("commit", str),
        ("tree", str),
        ("challenge", str),
        ("workflow-path", str),
        ("workflow-ref", str),
        ("release-workflow-path", str),
        ("phase1-artifact-digest", str),
    ):
        build.add_argument(f"--{name}", required=True, type=kind)
    for name in (
        "workflow-run-id",
        "workflow-run-attempt",
        "phase1-run-id",
        "phase1-run-attempt",
        "phase1-artifact-id",
    ):
        build.add_argument(f"--{name}", required=True, type=int)
    check = commands.add_parser("validate")
    check.add_argument("--evidence", required=True, type=Path)
    check.add_argument("--sidecar", type=Path)
    check.add_argument("--candidate-so", type=Path)
    check.add_argument("--policy-source", type=Path)
    check.add_argument("--ruleset-manifest", type=Path)
    check.add_argument("--ruleset-sidecar", type=Path)
    check.add_argument("--tag")
    check.add_argument("--commit")
    check.add_argument("--tree")
    check.add_argument("--challenge")
    check.add_argument("--workflow-run-id", type=int)
    check.add_argument("--workflow-run-attempt", type=int)
    check.add_argument("--phase1-run-id", type=int)
    check.add_argument("--phase1-run-attempt", type=int)
    check.add_argument("--phase1-artifact-id", type=int)
    check.add_argument("--phase1-artifact-digest")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "assemble":
            assemble(args)
        else:
            validate(args)
    except (ContractError, OSError) as exc:
        print(f"Round 9 Host evidence contract: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"Round 9 Host evidence contract: PASS: {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
