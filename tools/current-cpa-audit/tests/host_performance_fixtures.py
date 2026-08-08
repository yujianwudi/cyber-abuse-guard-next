from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any

from audit_contract import CPA_COMMIT, CPA_TAG, MOCK_CONTRACT, RUN_CONFIG_SCHEMA, canonical_bytes, sha256_bytes
from host_performance import (
    CANDIDATE_SCHEMA,
    CANDIDATE_STATUS,
    CONFIG_SCHEMA,
    MEASUREMENTS_SCHEMA,
    WORKLOAD_SCHEMA,
    build_config,
    build_evidence,
    tool_identities,
    validate_candidate_manifest,
    validate_measurements,
    validate_workload_manifest,
)


STAMP = "2026-08-06T00:00:00.000Z"


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def run_config() -> tuple[dict[str, Any], bytes]:
    value = {
        "corpus_manifest_sha256": "1" * 64,
        "identities": {
            "cag": {"commit": "1" * 40, "so_sha256": "2" * 64, "tree": "3" * 40},
            "cpa": {
                "binary_path": "/CLIProxyAPI",
                "binary_sha256": "4" * 64,
                "commit": CPA_COMMIT,
                "image_id": "sha256:" + "5" * 64,
                "image_ref": "registry.example/cpa@sha256:" + "6" * 64,
                "official_asset_name": "CLIProxyAPI_7.2.116_linux_amd64.tar.gz",
                "official_asset_sha256": "7" * 64,
                "repo_digest": "registry.example/cpa@sha256:" + "6" * 64,
                "tag": CPA_TAG,
            },
            "mock": {
                "contract": MOCK_CONTRACT,
                "image_id": "sha256:" + "8" * 64,
                "image_ref": "registry.example/mock@sha256:" + "9" * 64,
                "repo_digest": "registry.example/mock@sha256:" + "9" * 64,
                "source_sha256": "a" * 64,
            },
        },
        "paths": {
            "cag_repository": "/srv/cag",
            "cag_so": "/srv/cag.so",
            "corpus_manifest": "/srv/acquisition/corpus-manifest.json",
            "cpa_official_asset": "/srv/cpa.tar.gz",
            "evidence_directory": "/srv/evidence",
            "mock_source": "/srv/counted_mock.py",
        },
        "policy_sha256": "b" * 64,
        "run": {
            "cold_start_count": 3,
            "platform": "linux/amd64",
            "run_id": "unit-run",
            "seed": 1205,
        },
        "schema": RUN_CONFIG_SCHEMA,
    }
    return value, canonical_bytes(value) + b"\n"


def docker_container_info(
    *,
    image_id: str = "sha256:" + "5" * 64,
    security_options: list[Any] | None = None,
    pids_limit: Any = 256,
) -> dict[str, Any]:
    return {
        "Config": {"User": "1000:1000"},
        "HostConfig": {
            "CapAdd": [],
            "CapDrop": ["ALL"],
            "CpusetCpus": "0-3",
            "Memory": 536870912,
            "NanoCpus": 1000000000,
            "PidsLimit": pids_limit,
            "PortBindings": {},
            "Privileged": False,
            "PublishAllPorts": False,
            "ReadonlyRootfs": True,
            "RestartPolicy": {"Name": "no"},
            "SecurityOpt": (
                ["no-new-privileges:true"]
                if security_options is None
                else security_options
            ),
        },
        "Image": image_id,
        "NetworkSettings": {"Ports": {}},
        "RestartCount": 0,
        "State": {
            "Dead": False,
            "OOMKilled": False,
            "Restarting": False,
            "Running": True,
        },
    }


def candidate_manifest() -> tuple[dict[str, Any], bytes]:
    config, _ = run_config()
    names = (
        "cyber-abuse-guard-v0.16.so",
        "cyber-abuse-guard-v0.16.so.sha256",
        "cyber-abuse-guard_0.16_linux_amd64.zip",
        "build-metadata.json",
        "checksums.txt",
        "ruleset-manifest.json",
        "ruleset.sha256",
        "sbom.cdx.json",
    )
    artifacts = []
    for index, name in enumerate(names, start=1):
        digest = config["identities"]["cag"]["so_sha256"] if name.endswith(".so") else f"{index:x}" * 64
        artifacts.append({"bytes": 100 + index, "name": name, "sha256": digest})
    value = {
        "artifacts": artifacts,
        "commit": config["identities"]["cag"]["commit"],
        "dirty": False,
        "event": "pull_request",
        "run_attempt": "1",
        "run_id": "123456789",
        "schema": CANDIDATE_SCHEMA,
        "status": CANDIDATE_STATUS,
        "tree": config["identities"]["cag"]["tree"],
        "version": "0.16",
    }
    return value, canonical_bytes(value) + b"\n"


def workload_manifest() -> tuple[dict[str, Any], bytes]:
    workloads = []
    for identifier in ("fixed_workload", "ordinary", "five_repository_activation", "public"):
        request = {
            "body_path": f"{identifier}.json",
            "body_sha256": sha256_bytes((identifier + ":body").encode("utf-8")),
            "endpoint": "/v1/chat/completions",
            "expected_status_by_arm": {
                "cpa_cag": 403 if identifier == "five_repository_activation" else 200,
                "cpa_only": 200,
            },
        }
        workloads.append(
            {
                "id": identifier,
                "request_count": 1,
                "request_set_sha256": sha256_bytes(canonical_bytes([request])),
                "requests": [request],
            }
        )
    value = {
        "schema": WORKLOAD_SCHEMA,
        "workloads": workloads,
    }
    return value, canonical_bytes(value) + b"\n"


def performance_config() -> tuple[
    dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes
]:
    run, run_raw = run_config()
    candidate, candidate_raw = candidate_manifest()
    workload, workload_raw = workload_manifest()
    validate_candidate_manifest(candidate, run["identities"]["cag"])
    validate_workload_manifest(workload)
    config = build_config(
        run,
        run_raw,
        candidate,
        candidate_raw,
        workload_raw,
        approved_tool_identities=tool_identities(),
        seed=1206,
        paired_repetitions=3,
        warmup_seconds=30,
        measurement_seconds=120,
        min_success_samples_per_cell=1000,
        resource_sample_interval_ms=1000,
        queue_sample_interval_ms=100,
        warm_rss_sample_interval_seconds=1,
    )
    assert config["schema"] == CONFIG_SCHEMA
    return (
        config,
        canonical_bytes(config) + b"\n",
        run,
        run_raw,
        candidate,
        candidate_raw,
        workload,
        workload_raw,
    )


def _runtime(
    config: dict[str, Any], arm: str, ordinal: int
) -> dict[str, Any]:
    return {
        "cag_loaded": arm == "cpa_cag",
        "container_security": {
            "cpa": {"no_new_privileges": True, "pids_limit": 256},
            "mock": {"no_new_privileges": True, "pids_limit": 256},
        },
        "cpa_base_config_sha256": sha256_bytes(b"shared-observed-cpa-config"),
        "cpa_binary_sha256": config["identities"]["cpa"]["binary_sha256"],
        "cpa_container_id": f"container-{arm}",
        "cpa_image_id": config["identities"]["cpa"]["image_id"],
        "cpa_memory_bytes": 805306368,
        "cpa_oom_killed": False,
        "cpa_restart_count": 0,
        "cpuset_cpus": "0-15",
        "docker_comparable_sha256": sha256_bytes(b"shared-docker-comparable"),
        "loaded_cag_so_sha256": config["identities"]["cag"]["so_sha256"] if arm == "cpa_cag" else None,
        "mock_container_id": "container-mock",
        "mock_image_id": config["identities"]["mock"]["image_id"],
        "mock_oom_killed": False,
        "mock_restart_count": 0,
        "mock_source_sha256": config["identities"]["mock"]["source_sha256"],
        "nano_cpus": 1000000000,
        "panic_mentions": 0,
        "plugin_count": 1 if arm == "cpa_cag" else 0,
        "runtime_config_sha256": sha256_bytes(f"runtime:{arm}".encode("utf-8")),
    }


def _resources(elapsed_seconds: int = 120) -> list[dict[str, Any]]:
    return [
        {
            "cpu_percent": 100.0,
            "collector_host_cpu_percent": 0.0,
            "elapsed_ms": index * 1000,
            "final_sample": index == elapsed_seconds,
            "host_cpu_percent": 25.0,
            "inactive_cpa_cpu_percent": 0.0,
            "mock_cpu_percent": 60.0,
            "rss_mib": 100.0 + index / 1000,
            "steal_cpu_percent": 0.0,
        }
        for index in range(elapsed_seconds + 1)
    ]


def _mock_counters(expected_status: int, successful_samples: int) -> dict[str, Any]:
    count = successful_samples if expected_status == 200 else 0
    zero = {"auth": 0, "mock": 0, "provider": 0}
    observed = {"auth": count, "mock": count, "provider": count}
    return {"after": dict(observed), "before": zero, "delta": dict(observed)}


def retime_measurements(value: dict[str, Any], config: dict[str, Any]) -> None:
    cursor = datetime.fromisoformat(value["started_at"].replace("Z", "+00:00")) + timedelta(
        seconds=300
    )
    for cell in (*value["paired_cells"], *value["absolute_cells"]):
        cursor += timedelta(seconds=config["plan"]["warmup_seconds"])
        cell["started_at"] = _stamp(cursor)
        cursor += timedelta(seconds=float(cell["elapsed_seconds"]))
        cell["completed_at"] = _stamp(cursor)
    cursor += timedelta(seconds=config["plan"]["warmup_seconds"])
    value["warm_rss"]["started_at"] = _stamp(cursor)
    cursor += timedelta(seconds=float(value["warm_rss"]["elapsed_seconds"]))
    value["warm_rss"]["completed_at"] = _stamp(cursor)
    value["completed_at"] = _stamp(cursor)


def _queue(elapsed_seconds: int = 120) -> list[dict[str, Any]]:
    return [
        {
            "capacity": 256,
            "depth": 1,
            "elapsed_ms": index * 100,
            "final_sample": index == elapsed_seconds * 10,
        }
        for index in range(elapsed_seconds * 10 + 1)
    ]


def _cell(
    config: dict[str, Any],
    workload_map: dict[str, dict[str, Any]],
    *,
    phase: str,
    arm: str,
    workload: str,
    concurrency: int,
    repetition: int,
    order_index: int,
    ordinal: int,
) -> dict[str, Any]:
    if phase == "paired_ab":
        pair_id = f"c{concurrency}-r{repetition}"
        latency = 1.0 if arm == "cpa_only" else 1.05
        elapsed = 120.0
    else:
        pair_id = f"{workload}-c{concurrency}-r{repetition}"
        latency = {
            "ordinary": 2.0,
            "five_repository_activation": 100.0,
            "public": 100.0,
        }[workload]
        elapsed = 120.0
    return {
        "arm": arm,
        "completed_at": STAMP,
        "completed_requests": 1000,
        "concurrency": concurrency,
        "elapsed_seconds": elapsed,
        "infrastructure_errors": [],
        "latency_samples_ms": [latency] * 1000,
        "mock_counters": _mock_counters(
            403 if workload == "five_repository_activation" and arm == "cpa_cag" else 200,
            1000,
        ),
        "order_index": order_index,
        "pair_id": pair_id,
        "phase": phase,
        "planned_requests": 1000,
        "queue_samples": _queue(int(elapsed)) if arm == "cpa_cag" else [],
        "repetition": repetition,
        "request_set_sha256": workload_map[workload]["request_set_sha256"],
        "resource_samples": _resources(int(elapsed)),
        "runtime": _runtime(config, arm, ordinal),
        "started_at": STAMP,
        "successful_samples": 1000,
        "unexpected_http_errors": 0,
        "warmup_seconds": 30,
        "workload": workload,
    }


def measurements() -> tuple[
    dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes
]:
    config, config_raw, run, run_raw, candidate, candidate_raw, workload, workload_raw = performance_config()
    workload_map = {item["id"]: item for item in workload["workloads"]}
    paired: list[dict[str, Any]] = []
    absolute: list[dict[str, Any]] = []
    ordinal = 0
    from host_performance import paired_order

    for concurrency in (1, 4, 8, 16):
        for repetition in range(1, 4):
            for order_index, arm in enumerate(paired_order(1206, concurrency, repetition)):
                ordinal += 1
                paired.append(
                    _cell(
                        config,
                        workload_map,
                        phase="paired_ab",
                        arm=arm,
                        workload="fixed_workload",
                        concurrency=concurrency,
                        repetition=repetition,
                        order_index=order_index,
                        ordinal=ordinal,
                    )
                )
    for workload_id in ("ordinary", "five_repository_activation", "public"):
        for concurrency in (1, 4, 8, 16):
            for repetition in range(1, 4):
                ordinal += 1
                absolute.append(
                    _cell(
                        config,
                        workload_map,
                        phase="absolute",
                        arm="cpa_cag",
                        workload=workload_id,
                        concurrency=concurrency,
                        repetition=repetition,
                        order_index=0,
                        ordinal=ordinal,
                    )
                )
    warm_resources = [
        {
            "cpu_percent": 100.0,
            "collector_host_cpu_percent": 0.0,
            "elapsed_seconds": index,
            "host_cpu_percent": 25.0,
            "inactive_cpa_cpu_percent": 0.0,
            "mock_cpu_percent": 60.0,
            "rss_mib": 100.0 + (10.0 * index / 3600.0),
            "steal_cpu_percent": 0.0,
        }
        for index in range(3601)
    ]
    ordinal += 1
    value = {
        "absolute_cells": absolute,
        "baseline_eligibility": {
            "background_cpu_percent": [0.0] * 300,
            "sample_interval_seconds": 1,
            "steal_cpu_percent": [0.0] * 300,
        },
        "candidate_manifest_sha256": config["candidate_manifest_sha256"],
        "collector_tool_identities": dict(config["approved_tool_identities"]),
        "completed_at": STAMP,
        "config_sha256": sha256_bytes(config_raw),
        "host": {
            "architecture": "amd64",
            "boot_id_sha256": "c" * 64,
            "logical_cpu_count": 16,
            "machine_id_sha256": "d" * 64,
            "platform": "linux",
            "runner_uid": 1000,
        },
        "paired_cells": paired,
        "run_config_sha256": config["run_config_sha256"],
        "schema": MEASUREMENTS_SCHEMA,
        "started_at": STAMP,
        "warm_rss": {
            "arm": "cpa_cag",
            "completed_at": STAMP,
            "concurrency": 16,
            "elapsed_seconds": 3600.0,
            "infrastructure_errors": [],
            "measurement_window_seconds": 3600.0,
            "mock_counters": _mock_counters(200, 1000),
            "request_set_sha256": workload_map["fixed_workload"]["request_set_sha256"],
            "requests_completed": 1000,
            "resource_samples": warm_resources,
            "runtime": _runtime(config, "cpa_cag", ordinal),
            "started_at": STAMP,
            "unexpected_http_errors": 0,
            "warmup_seconds": 30,
            "workload": "fixed_workload",
        },
        "workload_manifest_sha256": config["workload_manifest_sha256"],
    }
    retime_measurements(value, config)
    return value, canonical_bytes(value) + b"\n", config, config_raw, workload, workload_raw, run, run_raw, candidate, candidate_raw


def evidence_bundle() -> tuple[dict[str, Any], dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], dict[str, Any]]:
    measurement, measurement_raw, config, config_raw, workload, _, _, _, _, _ = measurements()
    validated, summaries, baseline, extra = validate_measurements(
        measurement, measurement_raw, config, config_raw, workload
    )
    evidence = build_evidence(
        config, config_raw, validated, measurement_raw, summaries, baseline, extra
    )
    return evidence, measurement, measurement_raw, config, config_raw, workload, {
        "summaries": summaries,
        "baseline": baseline,
        "extra": extra,
    }


def clone(value: Any) -> Any:
    return copy.deepcopy(value)
