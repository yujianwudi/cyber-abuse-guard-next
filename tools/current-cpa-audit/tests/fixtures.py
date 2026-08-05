from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from audit_contract import (
    CLAIM_BOUNDARY,
    CORPUS_SCHEMA,
    EVIDENCE_SCHEMA,
    FIXED_REPOSITORIES,
    FIXED_SOURCE_PATHS,
    FIXED_SOURCE_RETENTION,
    MODES,
    PROTOCOLS,
    RESULT_SCHEMA,
    STREAM_VALUES,
    TEMPLATE_SHA256,
    build_execution_plan,
    canonical_bytes,
    review_sha256,
    sha256_bytes,
)


STAMP = "2026-08-04T00:00:00Z"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


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


def _event(expected: str, mode: str, request_hash: str, ordinal: int, malicious: bool) -> dict[str, Any] | None:
    if expected != "allow":
        if expected != "block_malicious_text":
            raise AssertionError(f"fixture only models malicious blocks, not {expected}")
        return {
            "action": "block",
            "category": "credential_theft",
            "coverage": "complete",
            "decision": "block_malicious_text",
            "decision_kind": "block_malicious_text",
            "explanation_schema": "decision-explanation-v2",
            "id": f"event-{ordinal}",
            "incomplete_reason": None,
            "mode": mode,
            "request_hash": request_hash,
        }
    if mode == "audit" and malicious:
        return {
            "action": "audit",
            "category": "credential_theft",
            "coverage": "complete",
            "decision": "audit_eligible_malicious_text",
            "decision_kind": "audit_eligible_malicious_text",
            "explanation_schema": "decision-explanation-v2",
            "id": f"event-{ordinal}",
            "incomplete_reason": None,
            "mode": mode,
            "request_hash": request_hash,
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
            "cag": {"commit": "1" * 40, "so_sha256": "1" * 64, "tree": "2" * 40},
            "configuration": {"input_sha256": "2" * 64, "runtime_sha256s": runtime_hashes},
            "cpa": {
                "binary_path": "/usr/local/bin/CLIProxyAPI",
                "binary_sha256": "3" * 64,
                "commit": "a88197f845c979132c8978ea223c6af05cc81536",
                "image_id": cpa_image,
                "official_asset_name": "CLIProxyAPI_7.2.116_linux_amd64.tar.gz",
                "official_asset_sha256": "4" * 64,
                "repo_digest": "registry.example/cpa@sha256:" + "5" * 64,
                "tag": "v7.2.116",
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
