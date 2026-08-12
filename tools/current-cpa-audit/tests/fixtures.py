from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from audit_contract import (
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CANDIDATE_ARTIFACT_NAME,
    CANDIDATE_MANIFEST_SCHEMA,
    CANDIDATE_MANIFEST_STATUS,
    CANDIDATE_REPOSITORY,
    CANDIDATE_WORKFLOW_NAME,
    CANDIDATE_WORKFLOW_PATH,
    CLAIM_BOUNDARY,
    CORPUS_SCHEMA,
    CPA_COMMIT,
    CPA_OFFICIAL_BINARY_SHA256,
    CPA_OFFICIAL_ASSET_NAME,
    CPA_OFFICIAL_ASSET_SHA256,
    CPA_TAG,
    EVIDENCE_SCHEMA,
    FIXED_REPOSITORIES,
    FIXED_SOURCE_PATHS,
    FIXED_SOURCE_RETENTION,
    MODES,
    PROTOCOLS,
    RESULT_SCHEMA,
    STREAM_VALUES,
    SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY,
    SUPPLEMENTAL_ZIP_CLAIM_BOUNDARY,
    SUPPLEMENTAL_ZIP_MANIFEST_SCHEMA,
    SUPPLEMENTAL_ZIP_RESULT_SCHEMA,
    TEMPLATE_SHA256,
    build_execution_plan,
    build_supplemental_execution_plan,
    canonical_bytes,
    review_sha256,
    sha256_bytes,
)
from supplemental_zip import _reviewed_cases


STAMP = "2026-08-04T00:00:00Z"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def candidate_provenance(
    *,
    commit: str,
    tree: str,
    so_sha256: str,
    manifest_sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "artifact": {
            "digest": "sha256:" + digest("candidate-artifact"),
            "id": "123456789",
            "name": CANDIDATE_ARTIFACT_NAME,
        },
        "event": "pull_request",
        "head_branch": "feature/candidate-provenance",
        "head_sha": digest("candidate-head")[:40],
        "manifest_sha256": manifest_sha256 or digest("candidate-manifest"),
        "repository": CANDIDATE_REPOSITORY,
        "run_attempt": "1",
        "run_id": "987654321",
        "schema": CANDIDATE_MANIFEST_SCHEMA,
        "source": {
            "commit": commit,
            "dirty": False,
            "tree": tree,
            "version": CAG_SOURCE_VERSION,
        },
        "so": {"name": CAG_SO_NAME, "sha256": so_sha256},
        "status": CANDIDATE_MANIFEST_STATUS,
        "workflow": {
            "name": CANDIDATE_WORKFLOW_NAME,
            "path": CANDIDATE_WORKFLOW_PATH,
        },
    }


def audit_candidate_manifest(
    *,
    commit: str,
    tree: str,
    so_sha256: str,
    run_id: str = "987654321",
    run_attempt: str = "1",
) -> dict[str, Any]:
    names = (
        CAG_SO_NAME,
        CAG_SO_NAME + ".sha256",
        f"cyber-abuse-guard_{CAG_SOURCE_VERSION}_linux_amd64.zip",
        "build-metadata.json",
        "checksums.txt",
        "ruleset-manifest.json",
        "ruleset.sha256",
        "sbom.cdx.json",
    )
    artifacts = [
        {
            "bytes": 100 + index,
            "name": name,
            "sha256": so_sha256 if name == CAG_SO_NAME else digest(f"candidate:{name}"),
        }
        for index, name in enumerate(names, start=1)
    ]
    return {
        "artifacts": artifacts,
        "commit": commit,
        "dirty": False,
        "event": "pull_request",
        "head_branch": "feature/candidate-provenance",
        "head_sha": digest("candidate-head")[:40],
        "repository": CANDIDATE_REPOSITORY,
        "run_attempt": run_attempt,
        "run_id": run_id,
        "schema": CANDIDATE_MANIFEST_SCHEMA,
        "status": CANDIDATE_MANIFEST_STATUS,
        "tree": tree,
        "version": CAG_SOURCE_VERSION,
        "workflow_name": CANDIDATE_WORKFLOW_NAME,
        "workflow_path": CANDIDATE_WORKFLOW_PATH,
    }


def approved_policy() -> dict[str, Any]:
    policy_path = Path(__file__).resolve().parent.parent / "repository-policy.json"
    policy = json.loads(policy_path.read_text("utf-8"))
    policy["reviewer"] = {
        "identity": "unit-test-approved-reviewer",
        "reviewed_at": STAMP,
        "status": "approved",
    }
    heads = {
        key: (f"{index:x}" * 40, f"{index + 5:x}" * 40)
        for index, key in enumerate(FIXED_REPOSITORIES, start=1)
    }
    for repository in policy["repositories"]:
        key = repository["key"]
        commit, tree = heads[key]
        for source in repository["paths"]:
            path = source["path"]
            text_sha256 = digest(f"text:{key}:{path}")
            source["reviewed_source"] = {
                "blob_sha1": hashlib.sha1(f"blob:{key}:{path}".encode()).hexdigest(),
                "commit": commit,
                "source_sha256": (
                    digest(f"source:{key}:{path}")
                    if source["archive_member"] is not None
                    else text_sha256
                ),
                "text_sha256": text_sha256,
                "tree": tree,
            }
    return policy


def receipt(key: str, suffix: str, *, commit: str | None = None, tree: str | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "api_body_sha256": digest(f"{key}:{suffix}"),
        "api_url": f"https://api.github.com/repos/{FIXED_REPOSITORIES[key]}/{suffix}",
        "etag": f'"{key}-{suffix}"',
        "observed_at": STAMP,
    }
    if commit is not None and tree is not None:
        value["commit"] = commit
        value["tree"] = tree
    return value


def semantic_case(
    key: str,
    path: str,
    commit: str,
    tree: str,
    *,
    malicious: bool = False,
    archive_member: str | None = None,
    semantic: Mapping[str, Any] | None = None,
    reviewer: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if semantic is not None:
        template = semantic["template_id"]
        label = semantic["label"]
        authorization = semantic["authorization"]
        ownership = semantic["ownership"]
        current_action = semantic["current_action"]
        actions = dict(semantic["expected_action_by_mode"])
        suffix = semantic["id_suffix"]
        label_reason = semantic["label_reason"]
    elif malicious:
        template = "activated-user-v1"
        label = "malicious_active"
        authorization = "unauthorized"
        ownership = "third_party"
        current_action = "active_execution"
        actions = {
            "audit": "allow",
            "balanced": "block_malicious_text",
            "strict": "block_malicious_text",
        }
        suffix = "active"
        label_reason = "Reviewed fixed fixture ground truth with explicit current-action ownership."
    else:
        template = "defensive-quote-v1" if key in {"mdx", "nerv"} else "raw-user-v1"
        label = "defensive_context" if template == "defensive-quote-v1" else "normal_control"
        authorization = "not_applicable"
        ownership = "third_party"
        current_action = "defensive_analysis" if template == "defensive-quote-v1" else "static_text"
        actions = {mode: "allow" for mode in MODES}
        suffix = "control"
        label_reason = "Reviewed fixed fixture ground truth with explicit current-action ownership."
    reviewer = reviewer or {
        "identity": "unit-test-approved-reviewer",
        "reviewed_at": STAMP,
        "status": "approved",
    }
    text_sha256 = digest(f"text:{key}:{path}")
    case: dict[str, Any] = {
        "authorization": authorization,
        "current_action": current_action,
        "expected_action_by_mode": actions,
        "id": f"{key}:{path}:{suffix}",
        "label": label,
        "label_reason": label_reason,
        "ownership": ownership,
        "reviewer": {
            "identity": reviewer["identity"],
            "review_sha256": "a" * 64,
            "reviewed_at": reviewer["reviewed_at"],
            "status": reviewer["status"],
        },
        "source": {
            "archive_member": archive_member,
            "blob_sha1": hashlib.sha1(f"blob:{key}:{path}".encode()).hexdigest(),
            "commit": commit,
            "corpus_file": f"corpus/{key}-{digest(path)[:12]}.txt",
            "path": path,
            "raw_etag": f'"raw-{key}"',
            "repository": FIXED_REPOSITORIES[key],
            "repository_key": key,
            "retention": FIXED_SOURCE_RETENTION[key],
            "source_sha256": (
                digest(f"source:{key}:{path}")
                if archive_member is not None
                else text_sha256
            ),
            "text_bytes": 10 + len(key),
            "text_sha256": text_sha256,
            "tree": tree,
        },
        "template": {"id": template, "sha256": TEMPLATE_SHA256[template]},
    }
    case["reviewer"]["review_sha256"] = review_sha256(case)
    return case


def manifest() -> dict[str, Any]:
    policy = approved_policy()
    policy_raw = canonical_bytes(policy) + b"\n"
    policy_repositories = {item["key"]: item for item in policy["repositories"]}
    observations: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    for index, key in enumerate(FIXED_REPOSITORIES, start=1):
        commit = f"{index:x}" * 40
        tree = f"{index + 5:x}" * 40
        observations.append(
            {
                "default_branch": "main",
                "metadata": receipt(key, "metadata"),
                "post": receipt(key, "post", commit=commit, tree=tree),
                "pre": receipt(key, "pre", commit=commit, tree=tree),
                "repository": FIXED_REPOSITORIES[key],
                "repository_key": key,
                "tree_api": {
                    **receipt(key, f"git/trees/{tree}?recursive=1"),
                    "api_url": f"https://api.github.com/repos/{FIXED_REPOSITORIES[key]}/git/trees/{tree}?recursive=1",
                },
            }
        )
        for source in policy_repositories[key]["paths"]:
            for semantic in source["semantic_cases"]:
                cases.append(
                    semantic_case(
                        key,
                        source["path"],
                        commit,
                        tree,
                        archive_member=source["archive_member"],
                        semantic=semantic,
                        reviewer=policy["reviewer"],
                    )
                )
    source_count = sum(len(paths) for paths in FIXED_SOURCE_PATHS.values())
    return {
        "acquired_at": STAMP,
        "artifact_status": "candidate",
        "claim_boundary": CLAIM_BOUNDARY,
        "filesystem_identity": {
            "acquisition_root": {"device": 1, "inode": 1},
            "corpus_directory": {"device": 1, "inode": 2},
        },
        "head_observations": observations,
        "policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
        "policy_review_status": "approved",
        "repository_count": 5,
        "schema": CORPUS_SCHEMA,
        "semantic_cases": cases,
        "source_count": source_count,
        "third_party_code_executions": 0,
        "unique_content_hashes": source_count,
        "unique_semantic_cases": len(cases),
    }


def _fabricated_supplemental_entries(
    entries: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    approved: list[dict[str, Any]] = []
    local_header_offset = 900
    for entry in entries:
        data_offset = local_header_offset + 100
        approved.append(
            {
                "compressed_bytes": entry["compressed_bytes"],
                "compression_method": entry["compression_method"],
                "content_sha256": entry["content_sha256"],
                "crc32": entry["crc32"],
                "data_offset": data_offset,
                "encoding": entry["encoding"],
                "entry_id": entry["entry_id"],
                "flags": 0,
                "local_header_offset": local_header_offset,
                "normalized_text_sha256": entry["normalized_text_sha256"],
                "path": entry["path"],
                "raw_name_sha256": entry["raw_name_sha256"],
                "text_bytes": entry["uncompressed_bytes"],
                "uncompressed_bytes": entry["uncompressed_bytes"],
            }
        )
        local_header_offset = data_offset + entry["compressed_bytes"]
    return approved


def supplemental_manifest_fixture() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    policy_path = Path(__file__).resolve().parent.parent / "supplemental-zip-policy.json"
    policy_raw = policy_path.read_bytes()
    policy = json.loads(policy_raw)
    approved = _fabricated_supplemental_entries(policy["entries"])
    supplemental = {
        "acquired_at": STAMP,
        "approved_entries": approved,
        "archive": {
            **SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY,
            "aggregate_ratio_milli": 1745,
            "data_descriptor_entries": 0,
            "duplicate_normalized_names": 0,
            "duplicate_raw_names": 0,
            "encrypted_entries": 0,
            "max_entry_ratio_milli": 7734,
            "max_entry_uncompressed_bytes": 1673696,
            "special_entries": 0,
            "symlink_entries": 0,
            "unicode_path_entries": 681,
            "unsafe_paths": 0,
            "utf8_flag_entries": 0,
            "zip64_entries": 0,
        },
        "artifact_status": "candidate",
        "claim_boundary": SUPPLEMENTAL_ZIP_CLAIM_BOUNDARY,
        "code_executions": 0,
        "member_text_files_created": 0,
        "policy_review_status": "approved",
        "policy_sha256": sha256_bytes(policy_raw),
        "reviewed_cases": _reviewed_cases(policy, approved),
        "schema": SUPPLEMENTAL_ZIP_MANIFEST_SCHEMA,
        "selected_entry_count": 4,
        "third_party_code_executions": 0,
        "unique_reviewed_cases": 7,
    }
    return supplemental, policy, policy_raw


def _event(
    expected: str,
    mode: str,
    request_hash: str,
    ordinal: int,
    malicious: bool,
    prefix: str = "event",
    winning_category: str = "credential_theft",
    winning_rule_id: str = "CRED-001",
) -> dict[str, Any] | None:
    if expected != "allow":
        if expected != "block_malicious_text":
            raise AssertionError(f"fixture only models malicious blocks, not {expected}")
        return {
            "action": "block",
            "category": winning_category,
            "coverage": "complete",
            "decision": "block_malicious_text",
            "decision_kind": "block_malicious_text",
            "explanation_schema": "decision-explanation-v2",
            "id": f"{prefix}-{ordinal}",
            "incomplete_reason": None,
            "mode": mode,
            "request_hash": request_hash,
            "winning_rule_id": winning_rule_id,
        }
    if mode == "audit" and malicious:
        return {
            "action": "audit",
            "category": winning_category,
            "coverage": "complete",
            "decision": "audit_malicious_text",
            "decision_kind": "audit_eligible_malicious_text",
            "explanation_schema": "decision-explanation-v2",
            "id": f"{prefix}-{ordinal}",
            "incomplete_reason": None,
            "mode": mode,
            "request_hash": request_hash,
            "winning_rule_id": winning_rule_id,
        }
    return None


def _container(role: str, image_id: str, index: int) -> dict[str, Any]:
    return {
        "cap_add": [],
        "cap_drop": ["ALL"],
        "host_port_bindings": 0,
        "id": f"{role}-container-{index}",
        "image_id": image_id,
        "memory_bytes": 134217728 if role == "mock" else 536870912,
        "pids_limit": 256,
        "privileged": False,
        "read_only_rootfs": True,
        "restart_policy": "no",
        "role": role,
        "running_before_stop": True,
        "security_opt": ["no-new-privileges:true"],
        "user": "1000:1000",
    }


def evidence_files(directory: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
    source_manifest = manifest()
    cases = {case["id"]: case for case in source_manifest["semantic_cases"]}
    plan = build_execution_plan(source_manifest, 1205, 3)
    per_cold: dict[int, bytearray] = {1: bytearray(), 2: bytearray(), 3: bytearray()}
    orders: dict[int, list[tuple[str, str, str, bool]]] = {1: [], 2: [], 3: []}
    rows: list[dict[str, Any]] = []
    for ordinal, entry in enumerate(plan, start=1):
        case = cases[entry.semantic_case_id]
        expected = case["expected_action_by_mode"][entry.mode]
        request_identity = f"{entry.semantic_case_id}:{entry.protocol}:{entry.stream}"
        request_hash = "sha256:" + digest(f"audit-request:{request_identity}")
        blocked = expected != "allow"
        row = {
            "actual_action": expected,
            "audit_event": _event(expected, entry.mode, request_hash, ordinal, case["label"] == "malicious_active"),
            "cold_start": entry.cold_start,
            "error_contract": (
                {
                    "checked": True,
                    "content_type": "application/json; charset=utf-8",
                    "no_store": True,
                    "nosniff": True,
                    "schema_valid": True,
                }
                if blocked
                else {
                    "checked": False,
                    "content_type": None,
                    "no_store": None,
                    "nosniff": None,
                    "schema_valid": None,
                }
            ),
            "execution_id": f"unit-run:{ordinal:08d}",
            "expected_action": expected,
            "expected_action_by_mode": dict(case["expected_action_by_mode"]),
            "expected_audit_request_hash": request_hash,
            "http_status": 403 if blocked else 200,
            "infrastructure_error": None,
            "latency_ms": 1.0,
            "mode": entry.mode,
            "ordinal": ordinal,
            "passed": True,
            "protocol": entry.protocol,
            "request_sha256": digest(f"request:{request_identity}"),
            "response_bytes": 10,
            "response_sha256": digest(f"response:{ordinal}"),
            "schema": RESULT_SCHEMA,
            "semantic_case_id": entry.semantic_case_id,
            "side_effect_deltas": (
                {"auth": 0, "mock": 0, "provider": 0, "usage": 0}
                if blocked
                else {"auth": 1, "mock": 1, "provider": 1, "usage": 1}
            ),
            "source_text_sha256": case["source"]["text_sha256"],
            "stream": entry.stream,
            "stream_terminated": not blocked,
            "template_sha256": case["template"]["sha256"],
            "usage_recorded": not blocked,
        }
        raw = canonical_bytes(row) + b"\n"
        rows.append(row)
        per_cold[entry.cold_start].extend(raw)
        orders[entry.cold_start].append(
            (entry.mode, entry.semantic_case_id, entry.protocol, entry.stream)
        )
    results_path = directory / "results.jsonl"
    results_path.write_bytes(b"".join(canonical_bytes(row) + b"\n" for row in rows))

    supplemental_manifest, supplemental_policy, supplemental_policy_raw = (
        supplemental_manifest_fixture()
    )
    supplemental_cases = {
        case["id"]: case for case in supplemental_manifest["reviewed_cases"]
    }
    supplemental_plan = build_supplemental_execution_plan(
        supplemental_manifest, 1205, 3
    )
    supplemental_per_cold: dict[int, bytearray] = {
        1: bytearray(),
        2: bytearray(),
        3: bytearray(),
    }
    supplemental_orders: dict[int, list[tuple[str, str, str, bool]]] = {
        1: [],
        2: [],
        3: [],
    }
    supplemental_rows: list[dict[str, Any]] = []
    for ordinal, entry in enumerate(supplemental_plan, start=1):
        case = supplemental_cases[entry.semantic_case_id]
        expected = case["expected_action_by_mode"][entry.mode]
        request_identity = (
            f"supplemental:{entry.semantic_case_id}:{entry.protocol}:{entry.stream}"
        )
        request_hash = "sha256:" + digest(f"audit-request:{request_identity}")
        blocked = expected != "allow"
        row = {
            "actual_action": expected,
            "audit_event": _event(
                expected,
                entry.mode,
                request_hash,
                ordinal,
                case["label"] == "malicious_active",
                "supplemental-event",
                case["expected_winning_category"] or "credential_theft",
                case["expected_winning_rule_id"] or "CRED-001",
            ),
            "cold_start": entry.cold_start,
            "error_contract": (
                {
                    "checked": True,
                    "content_type": "application/json; charset=utf-8",
                    "no_store": True,
                    "nosniff": True,
                    "schema_valid": True,
                }
                if blocked
                else {
                    "checked": False,
                    "content_type": None,
                    "no_store": None,
                    "nosniff": None,
                    "schema_valid": None,
                }
            ),
            "execution_id": f"unit-run:supplemental:{ordinal:08d}",
            "expected_action": expected,
            "expected_action_by_mode": dict(case["expected_action_by_mode"]),
            "expected_audit_request_hash": request_hash,
            "http_status": 403 if blocked else 200,
            "infrastructure_error": None,
            "latency_ms": 1.0,
            "mode": entry.mode,
            "ordinal": ordinal,
            "passed": True,
            "protocol": entry.protocol,
            "request_sha256": digest(f"request:{request_identity}"),
            "response_bytes": 10,
            "response_sha256": digest(f"supplemental-response:{ordinal}"),
            "schema": SUPPLEMENTAL_ZIP_RESULT_SCHEMA,
            "side_effect_deltas": (
                {"auth": 0, "mock": 0, "provider": 0, "usage": 0}
                if blocked
                else {"auth": 1, "mock": 1, "provider": 1, "usage": 1}
            ),
            "source_text_sha256": case["source"]["normalized_text_sha256"],
            "stream": entry.stream,
            "stream_terminated": not blocked,
            "supplemental_case_id": entry.semantic_case_id,
            "template_sha256": case["template"]["sha256"],
            "usage_recorded": not blocked,
        }
        raw = canonical_bytes(row) + b"\n"
        supplemental_rows.append(row)
        supplemental_per_cold[entry.cold_start].extend(raw)
        supplemental_orders[entry.cold_start].append(
            (entry.mode, entry.semantic_case_id, entry.protocol, entry.stream)
        )
    supplemental_results_path = directory / "supplemental-zip-results.jsonl"
    supplemental_results_path.write_bytes(
        b"".join(canonical_bytes(row) + b"\n" for row in supplemental_rows)
    )
    supplemental_manifest_raw = canonical_bytes(supplemental_manifest) + b"\n"
    (directory / "supplemental-zip-policy.json").write_bytes(
        supplemental_policy_raw
    )
    (directory / "supplemental-zip-manifest.json").write_bytes(
        supplemental_manifest_raw
    )

    cpa_image = "sha256:" + "a" * 64
    mock_image = "sha256:" + "b" * 64
    runtime_hashes = [digest(f"runtime:{index}") for index in range(1, 4)]
    cold_starts: list[dict[str, Any]] = []
    for index in range(1, 4):
        cold_starts.append(
            {
                "completed_at": STAMP,
                "containers": {
                    "cpa": _container("cpa", cpa_image, index),
                    "mock": _container("mock", mock_image, index),
                },
                "execution_count": len(per_cold[index].splitlines()),
                "index": index,
                "network": {
                    "attachable": False,
                    "driver": "bridge",
                    "host_ports": 0,
                    "ingress": False,
                    "internal": True,
                    "ipv6": False,
                    "members": ["cpa", "mock"],
                    "name": "unit-run-net",
                },
                "order_sha256": sha256_bytes(canonical_bytes(orders[index])),
                "results_sha256": sha256_bytes(bytes(per_cold[index])),
                "runtime": {
                    "cpa_exit_code": 0,
                    "cpa_oom_killed": False,
                    "cpa_restart_count": 0,
                    "fatal_mentions": 0,
                    "mock_exit_code": 0,
                    "mock_oom_killed": False,
                    "mock_restart_count": 0,
                    "panic_mentions": 0,
                    "plugin_error_mentions": 0,
                },
                "runtime_config_sha256": runtime_hashes[index - 1],
                "sqlite": {
                    "database_sha256": digest(f"database:{index}"),
                    "quick_check": "ok",
                    "schema_version": 6,
                    "wal_checkpoint": {"busy": 0, "checkpointed_frames": 0, "log_frames": 0},
                },
                "started_at": STAMP,
                "stop": {
                    "checkpoint_after_stop": True,
                    "cpa_graceful": True,
                    "forced_kill_used": False,
                    "mock_graceful": True,
                },
                "supplemental_execution_count": len(
                    supplemental_per_cold[index].splitlines()
                ),
                "supplemental_order_sha256": sha256_bytes(
                    canonical_bytes(supplemental_orders[index])
                ),
                "supplemental_results_sha256": sha256_bytes(
                    bytes(supplemental_per_cold[index])
                ),
            }
        )

    resources: list[dict[str, Any]] = []
    for _ in range(3):
        for kind, name in (("container", "unit-run-cpa"), ("container", "unit-run-mock")):
            resources.append(
                {
                    "action": "removed",
                    "expected_label": "unit-run",
                    "kind": kind,
                    "name": name,
                    "observed_label": "unit-run",
                }
            )
    resources.append(
        {
            "action": "removed",
            "expected_label": "unit-run",
            "kind": "network",
            "name": "unit-run-net",
            "observed_label": "unit-run",
        }
    )
    empty_hash = sha256_bytes(canonical_bytes([]))
    machine = {
        "business_snapshots": {
            "after": [],
            "after_sha256": empty_hash,
            "before": [],
            "before_sha256": empty_hash,
            "unchanged": True,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "cleanup": {
            "all_owned_resources_absent": True,
            "checkpoint_attempts": 3,
            "global_prune_used": False,
            "graceful_stop_attempts": 6,
            "images_removed": False,
            "resources": resources,
            "supplemental_input_archive_preserved": True,
            "supplemental_member_text_files_created": 0,
            "supplemental_member_text_files_removed": 0,
            "supplemental_member_text_retained": False,
            "third_party_text_files_removed": source_manifest["source_count"],
            "third_party_text_retained": False,
        },
        "cold_starts": cold_starts,
        "completed_at": STAMP,
        "corpus": {
            "artifact_status": source_manifest["artifact_status"],
            "manifest_path": "corpus-manifest.json",
            "manifest_sha256": sha256_bytes(canonical_bytes(source_manifest) + b"\n"),
            "policy_review_status": source_manifest["policy_review_status"],
            "repository_count": 5,
            "source_count": source_manifest["source_count"],
            "unique_content_hashes": source_manifest["unique_content_hashes"],
            "unique_semantic_cases": source_manifest["unique_semantic_cases"],
        },
        "identities": {
            "candidate": candidate_provenance(
                commit="1" * 40,
                tree="2" * 40,
                so_sha256="1" * 64,
            ),
            "cag": {
                "commit": "1" * 40,
                "so_name": CAG_SO_NAME,
                "so_sha256": "1" * 64,
                "source_version": CAG_SOURCE_VERSION,
                "tree": "2" * 40,
            },
            "configuration": {"input_sha256": "2" * 64, "runtime_sha256s": runtime_hashes},
            "cpa": {
                "binary_path": "/usr/local/bin/CLIProxyAPI",
                "binary_sha256": CPA_OFFICIAL_BINARY_SHA256,
                "commit": CPA_COMMIT,
                "image_id": cpa_image,
                "official_asset_name": CPA_OFFICIAL_ASSET_NAME,
                "official_asset_sha256": CPA_OFFICIAL_ASSET_SHA256,
                "repo_digest": "registry.example/cpa@sha256:" + "5" * 64,
                "tag": CPA_TAG,
            },
            "mock": {
                "contract": "cag-current-cpa-counted-mock/v1",
                "image_id": mock_image,
                "repo_digest": "registry.example/mock@sha256:" + "6" * 64,
                "source_sha256": "7" * 64,
            },
            "runner": {
                "audit_contract_sha256": "8" * 64,
                "bundle_sha256": "9" * 64,
                "machine_schema_sha256": "a" * 64,
                "mock_source_sha256": "7" * 64,
                "policy_sha256": source_manifest["policy_sha256"],
                "run_source_sha256": "b" * 64,
            },
        },
        "infrastructure_errors": [],
        "run": {"cold_start_count": 3, "platform": "linux/amd64", "run_id": "unit-run", "seed": 1205},
        "schema": EVIDENCE_SCHEMA,
        "started_at": STAMP,
        "supplemental_zip_manifest": {
            "archive_bytes": supplemental_manifest["archive"]["bytes"],
            "archive_sha256": supplemental_manifest["archive"]["sha256"],
            "code_executions": 0,
            "manifest_path": "supplemental-zip-manifest.json",
            "manifest_sha256": sha256_bytes(supplemental_manifest_raw),
            "member_text_files_created": 0,
            "policy_path": "supplemental-zip-policy.json",
            "policy_sha256": sha256_bytes(supplemental_policy_raw),
            "selected_entry_count": 4,
            "third_party_code_executions": 0,
            "unique_reviewed_cases": 7,
        },
        "supplemental_zip_results": {
            "modes": list(MODES),
            "protocols": list(PROTOCOLS),
            "results_path": "supplemental-zip-results.jsonl",
            "results_sha256": sha256_file_bytes(
                supplemental_results_path.read_bytes()
            ),
            "streams": list(STREAM_VALUES),
            "supplemental_executions": len(supplemental_rows),
        },
        "supplemental_zip_summary": {
            "allow_executions": sum(
                row["actual_action"] == "allow" for row in supplemental_rows
            ),
            "block_incomplete_inspection_executions": sum(
                row["actual_action"] == "block_incomplete_inspection"
                for row in supplemental_rows
            ),
            "block_malicious_text_executions": sum(
                row["actual_action"] == "block_malicious_text"
                for row in supplemental_rows
            ),
            "code_executions": 0,
            "malicious_case_count": sum(
                case["label"] == "malicious_active"
                for case in supplemental_cases.values()
            ),
            "passed_executions": len(supplemental_rows),
            "third_party_code_executions": 0,
            "total_executions": len(supplemental_rows),
            "transport_error_executions": sum(
                row["actual_action"] == "transport_error"
                for row in supplemental_rows
            ),
        },
        "third_party_code_executions": 0,
        "transport": {
            "modes": list(MODES),
            "protocols": list(PROTOCOLS),
            "results_path": "transport-results.jsonl",
            "results_sha256": sha256_file_bytes(results_path.read_bytes()),
            "streams": list(STREAM_VALUES),
            "transport_executions": len(rows),
        },
    }
    return source_manifest, machine, results_path


def sha256_file_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
