"""Synthetic closed evidence fixtures shared by Round 9 contract tests."""

from __future__ import annotations

from typing import Any


def _wilson(successes: int, total: int) -> tuple[int, int]:
    z = 1.959963984540054
    probability = successes / total
    z2 = z * z
    denominator = 1 + z2 / total
    center = probability + z2 / (2 * total)
    margin = z * (
        probability * (1 - probability) / total + z2 / (4 * total * total)
    ) ** 0.5
    return (
        round(max(0.0, (center - margin) / denominator) * 10_000),
        round(min(1.0, (center + margin) / denominator) * 10_000),
    )


def _binding(character: str, *, schema: str | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"bytes": 1024, "sha256": character * 64}
    if schema is not None:
        value["schema"] = schema
    return value


def runtime_checks(phase: str = "post_evaluation") -> dict[str, Any]:
    """Closed synthetic PASS used only by contract/unit tests."""

    return {
        "schema": "round9-external-cpa-runtime-checks/v1",
        "state": "PASS",
        "phase": phase,
        "audit_database": {
            "observed": True,
            "quick_check": "ok",
            "schema_version": 6,
            "migration_versions": [1, 2, 3, 4, 5, 6],
            "wal_checkpoint_passed": True,
            "evaluation_event_delta": 1083 if phase == "post_evaluation" else 0,
        },
        "restart_recovery": {
            "observed": True,
            "controlled_restart_count": 1,
            "unexpected_restart_count": 0,
            "post_restart_mode_verified": "audit",
        },
        "panic_recovery": {
            "observed": True,
            "probe_passed": True,
            "panic_count": 0,
            "fatal_count": 0,
            "plugin_error_count": 0,
            "request_body_log_markers": 0,
        },
        "usage_queue": {
            "observed": True,
            "allowed_request_delta": 1,
            "blocked_request_delta": 0,
            "evaluation_allowed_delta": 7562 if phase == "post_evaluation" else 0,
            "evaluation_blocked_delta": 721 if phase == "post_evaluation" else 0,
            "post_evaluation_quiet": True,
        },
        "raw_capture": {
            "observed": True,
            "default_disabled": True,
            "normal_request_records": 0,
            "normal_request_plaintext_persisted": False,
            "evaluation_request_records": 0,
            "evaluation_plaintext_persisted": False,
        },
        "lifecycle": {
            "observed": True,
            "exit_code": 0,
            "oom_killed": False,
            "unexpected_restart_count": 0,
        },
    }


def decision_audit() -> dict[str, Any]:
    return {
        "schema": "round9-external-decision-audit/v2",
        "state": "PASS",
        "observed": True,
        "expectations_sha256": "a" * 64,
        "expectation_count": 8283,
        "required_expectation_count": 1083,
        "optional_expectation_count": 7200,
        "matched_count": 1083,
        "optional_persisted_count": 0,
        "optional_missing_count": 7200,
        "unexpected_event_count": 0,
        "decision_kind_counts": {
            "audit_eligible_malicious_text": 360,
            "audit_ineligible_risk": 2,
            "block_malicious_text": 720,
            "block_incomplete_inspection": 1,
        },
        "group_counts": {
            "benign": 0,
            "malicious_audit": 360,
            "malicious_enforcement": 720,
            "incomplete_non_strict": 2,
            "strict_incomplete": 1,
        },
        "subject_state_rows": 0,
        "incomplete_malicious_category_count": 0,
        "incomplete_winner_count": 0,
        "correlation_sha256": "b" * 64,
        "correlation_samples": [
            {
                "request_id_hmac_sha256": "c" * 64,
                "request_hash_hmac_sha256": "d" * 64,
                "event_id_sha256": "e" * 64,
                "mode": "strict",
                "decision_kind": "block_incomplete_inspection",
            }
        ],
    }


def development_evidence(
    *,
    tag_object_sha: str = "1" * 40,
    commit: str = "2" * 40,
    tree: str = "3" * 40,
    classifier_version: str = "classifier-policy-v8-round9-test",
    classifier_sha256: str = "4" * 64,
    ruleset_version: str = "1.0.10",
    ruleset_sha256: str = "5" * 64,
) -> dict[str, Any]:
    lower, upper = _wilson(60, 60)
    paired_category = {
        "samples": 60,
        "blocked": 60,
        "recall_basis_points": 10_000,
        "wilson_lower_bound_basis_points": lower,
        "wilson_upper_bound_basis_points": upper,
    }
    return {
        "schema": "round9-development-evidence/v1",
        "state": "PASS",
        "candidate": {
            "tag": "v0.16-rc.3",
            "tag_object_sha": tag_object_sha,
            "commit": commit,
            "tree": tree,
            "classifier": {
                "version": classifier_version,
                "sha256": classifier_sha256,
            },
            "ruleset": {"version": ruleset_version, "sha256": ruleset_sha256},
        },
        "runtime": "go1.26.4",
        "platform": "linux/amd64",
        "corpus": {
            "development_benign": {
                "name": "round9-development-benign-v1",
                "manifest": _binding("6"),
                "cases": _binding("7"),
                "unique_semantic_samples": 1200,
                "serialized_route_executions": 7200,
                "blocked_semantic_samples": 0,
                "blocked_route_executions": 0,
            },
            "paired_malicious": {
                "name": "round9-development-paired-malicious-v3",
                "source_report_schema": "round9-development-paired-malicious-report/v3",
                "manifest_version": 2,
                "manifest": _binding("8"),
                "cases": _binding("9"),
                "label_audit": _binding("a"),
                "benign_manifest": _binding("b"),
                "benign_cases": _binding("c"),
                "unique_semantic_samples": 120,
                "semantic_blocked": 120,
                "serialized_route_executions": 960,
                "enforcement_route_executions": 960,
                "audit_route_executions": 0,
                "passed_route_executions": 960,
                "audit_allowed_route_executions": 0,
                "audit_policy_blocked": 0,
                "recall_basis_points": 10_000,
                "per_category": {
                    "credential_theft": dict(paired_category),
                    "malware_execution": dict(paired_category),
                },
            },
            "public_adversarial": {
                "name": "round9-public-adversarial-v5",
                "manifest": _binding("d"),
                "development_only": True,
                "independent_holdout": False,
                "third_party_code_executed": False,
                "metrics": {
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
                },
            },
        },
        "audit_contract": {
            "schema_version": 6,
            "raw_capture_schema_version": 4,
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
        },
        "machine_reports": {
            "development_benign": _binding(
                "e", schema="round9-development-benign-corpus-report/v1"
            ),
            "paired_malicious": _binding(
                "f", schema="round9-development-paired-malicious-machine-report/v1"
            ),
            "public_adversarial": _binding(
                "1", schema="round9-public-adversarial-report/v5"
            ),
            "audit_contract": _binding("2", schema="round9-audit-contract-report/v1"),
        },
        "producer_logs": {
            "paired_malicious": _binding("3"),
            "public_adversarial": _binding("4"),
            "audit_contract": _binding("5"),
        },
        "claim_boundary": (
            "Candidate-owned development evidence only; it is not independent evidence, "
            "does not authorize production, and executed no third-party repository code."
        ),
    }
