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
            "evaluation_event_delta": 1203 if phase == "post_evaluation" else 0,
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
            "evaluation_allowed_delta": 7602 if phase == "post_evaluation" else 0,
            "evaluation_blocked_delta": 801 if phase == "post_evaluation" else 0,
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
        "schema": "round9-external-decision-audit/v3",
        "state": "PASS",
        "observed": True,
        "expectations_sha256": "a" * 64,
        "expectation_count": 8403,
        "required_expectation_count": 1203,
        "optional_expectation_count": 7200,
        "matched_count": 1203,
        "optional_persisted_count": 0,
        "optional_missing_count": 7200,
        "unexpected_event_count": 0,
        "decision_kind_counts": {
            "allow_clean": 0,
            "audit_eligible_malicious_text": 400,
            "audit_ineligible_risk": 2,
            "block_malicious_text": 800,
            "block_incomplete_inspection": 1,
            "block_opaque_media": 0,
            "block_subject_risk": 0,
        },
        "group_counts": {
            "benign": 0,
            "malicious_audit": 360,
            "malicious_enforcement": 720,
            "incomplete_non_strict": 2,
            "strict_incomplete": 1,
            "public_development": 120,
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


def public_counted_mock(*, hard_policy_blocked: int = 0) -> dict[str, Any]:
    families = {
        "historical_unique": ("historical_default_payload", 8, 96, 64, 32, 32),
        "branch_head": ("branch_head_payload", 1, 12, 8, 4, 4),
        "unmerged_candidate_carrier": (
            "unmerged_candidate_carrier",
            1,
            12,
            8,
            4,
            4,
        ),
    }
    remaining_hard = hard_policy_blocked
    rows: dict[str, Any] = {}
    decision_keys = (
        "allow_clean",
        "audit_ineligible_risk",
        "audit_eligible_malicious_text",
        "block_malicious_text",
        "block_incomplete_inspection",
        "block_opaque_media",
        "block_subject_risk",
    )
    for family, (role, unique, routes, blocked, upstream, usage) in families.items():
        hard = min(remaining_hard, blocked)
        remaining_hard -= hard
        decisions = {key: 0 for key in decision_keys}
        decisions["audit_eligible_malicious_text"] = unique * 4
        decisions["block_malicious_text"] = unique * 8
        rows[family] = {
            "corpus_role": role,
            "unique_payloads": unique,
            "serialized_executions": routes,
            "local_blocked": blocked,
            "upstream_delta": upstream,
            "usage_delta": usage,
            "hard_policy_blocked": hard,
            "decision_kind_counts": decisions,
        }
    if remaining_hard:
        raise ValueError("synthetic hard-policy count exceeds public block count")
    total_decisions = {
        key: sum(row["decision_kind_counts"][key] for row in rows.values())
        for key in decision_keys
    }
    return {
        "schema": "round9-public-counted-mock/v1",
        "state": "PASS",
        "development_only": True,
        "independent_holdout": False,
        "third_party_code_executed": False,
        "manifest": {
            "schema": "round9-public-adversarial-corpus/v11",
            "dataset": "round9-public-adversarial-v11",
            "bytes": 1024,
            "sha256": "d" * 64,
        },
        "route_matrix": {
            "modes": ["audit", "balanced", "strict"],
            "protocols": ["openai_chat", "openai_responses"],
            "streams": ["nonstream", "stream"],
            "routes_per_payload": 12,
        },
        "families": rows,
        "total": {
            "unique_payloads": 10,
            "serialized_executions": 120,
            "local_blocked": 80,
            "upstream_delta": 40,
            "usage_delta": 40,
            "hard_policy_blocked": hard_policy_blocked,
            "decision_kind_counts": total_decisions,
        },
        "claim_boundary": (
            "Public, candidate-visible development regression payloads executed as exact decoded bytes "
            "through loopback-only CPA counted-Mock routes; this is Host transport and decision evidence, "
            "not independent holdout evidence or production approval. Candidate-owned manifest provenance "
            "is format/hash checked but does not independently prove third-party source extraction."
        ),
    }


def public_counted_mock_transport(*, hard_policy_blocked: int = 0) -> dict[str, Any]:
    counted = public_counted_mock(hard_policy_blocked=hard_policy_blocked)
    family_keys = {
        "corpus_role",
        "unique_payloads",
        "serialized_executions",
        "local_blocked",
        "upstream_delta",
        "usage_delta",
        "hard_policy_blocked",
    }
    return {
        "schema": "round9-public-counted-mock-transport/v1",
        "manifest": dict(counted["manifest"]),
        "route_matrix": dict(counted["route_matrix"]),
        "families": {
            family: {key: value for key, value in row.items() if key in family_keys}
            for family, row in counted["families"].items()
        },
        "total": {
            key: value
            for key, value in counted["total"].items()
            if key != "decision_kind_counts"
        },
    }


def public_decision_audit() -> dict[str, Any]:
    counted = public_counted_mock()
    return {
        "schema": "round9-public-cpa-decision-audit/v1",
        "manifest": dict(counted["manifest"]),
        "route_matrix": dict(counted["route_matrix"]),
        "families": {
            family: {
                "corpus_role": row["corpus_role"],
                "unique_payloads": row["unique_payloads"],
                "serialized_executions": row["serialized_executions"],
                "decision_kind_counts": dict(row["decision_kind_counts"]),
            }
            for family, row in counted["families"].items()
        },
        "total": {
            "unique_payloads": counted["total"]["unique_payloads"],
            "serialized_executions": counted["total"]["serialized_executions"],
            "decision_kind_counts": dict(counted["total"]["decision_kind_counts"]),
        },
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
                "passed_route_executions": 960,
                "recall_basis_points": 10_000,
                "per_category": {
                    "credential_theft": dict(paired_category),
                    "malware_execution": dict(paired_category),
                },
            },
            "public_adversarial": {
                "name": "round9-public-adversarial-v11",
                "manifest": _binding("d"),
                "development_only": True,
                "independent_holdout": False,
                "third_party_code_executed": False,
                "payload_records": 24,
                "candidate_carrier_executions": 1,
                "candidate_carriers_not_provided": 0,
                "scenario_payload_executions": 24,
                "serialized_route_executions": 120,
                "direct_active_blocked": 12,
                "direct_active_allowed": 12,
                "unique_historical_payloads": 8,
                "unique_branch_head_payloads": 1,
                "unique_current_prompt_like_payloads": 14,
                "unique_formal_payloads": 23,
                "unmerged_candidate_carriers": 1,
                "nondefault_branch_candidate_carriers": 5,
                "release_assets_reviewed": 16,
                "release_assets_with_prompt_entries": 4,
                "release_asset_metadata_records": 199,
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
                "1", schema="round9-public-adversarial-report/v11"
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
