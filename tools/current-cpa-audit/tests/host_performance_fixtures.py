from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any

from audit_contract import (
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CANDIDATE_ARTIFACT_NAME,
    CANDIDATE_REPOSITORY,
    CANDIDATE_WORKFLOW_NAME,
    CANDIDATE_WORKFLOW_PATH,
    CPA_COMMIT,
    CPA_OFFICIAL_BINARY_SHA256,
    CPA_OFFICIAL_ASSET_NAME,
    CPA_OFFICIAL_ASSET_SHA256,
    CPA_TAG,
    MOCK_CONTRACT,
    RUN_CONFIG_SCHEMA,
    candidate_identity as build_candidate_identity,
    canonical_bytes,
    sha256_bytes,
)
from host_performance import (
    CANDIDATE_SCHEMA,
    CANDIDATE_STATUS,
    CONFIG_SCHEMA,
    LARGE_PAYLOAD_BASELINE_SAMPLES,
    LARGE_PAYLOAD_BYTES,
    LARGE_PAYLOAD_CONCURRENCY,
    LARGE_PAYLOAD_REQUESTS,
    LARGE_PAYLOAD_RSS_SAMPLE_INTERVAL_MS,
    LARGE_PAYLOAD_WORKLOAD,
    MEASUREMENTS_SCHEMA,
    MOUNT_PROJECTION_BOUNDARY,
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


def _cag_identity() -> dict[str, Any]:
    return {
        "commit": "1" * 40,
        "so_name": CAG_SO_NAME,
        "so_sha256": "2" * 64,
        "source_version": CAG_SOURCE_VERSION,
        "tree": "3" * 40,
    }


def _candidate_manifest_value(cag: dict[str, Any]) -> dict[str, Any]:
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
    artifacts = []
    for index, name in enumerate(names, start=1):
        digest = cag["so_sha256"] if name == CAG_SO_NAME else f"{index:x}" * 64
        artifacts.append({"bytes": 100 + index, "name": name, "sha256": digest})
    return {
        "artifacts": artifacts,
        "commit": cag["commit"],
        "dirty": False,
        "event": "pull_request",
        "head_branch": "agent/cpa-v7.2.125-v1-rc1",
        "head_sha": "4" * 40,
        "repository": CANDIDATE_REPOSITORY,
        "run_attempt": "1",
        "run_id": "123456789",
        "schema": CANDIDATE_SCHEMA,
        "status": CANDIDATE_STATUS,
        "tree": cag["tree"],
        "version": CAG_SOURCE_VERSION,
        "workflow_name": CANDIDATE_WORKFLOW_NAME,
        "workflow_path": CANDIDATE_WORKFLOW_PATH,
    }


def run_config() -> tuple[dict[str, Any], bytes]:
    cag = _cag_identity()
    manifest = _candidate_manifest_value(cag)
    manifest_raw = canonical_bytes(manifest) + b"\n"
    value = {
        "corpus_manifest_sha256": "1" * 64,
        "identities": {
            "cag": cag,
            "candidate": build_candidate_identity(
                manifest,
                manifest_raw,
                cag_identity=cag,
                artifact_id="987654321",
                artifact_name=CANDIDATE_ARTIFACT_NAME,
                artifact_digest="sha256:" + "e" * 64,
            ),
            "cpa": {
                "binary_path": "/CLIProxyAPI",
                "binary_sha256": CPA_OFFICIAL_BINARY_SHA256,
                "commit": CPA_COMMIT,
                "image_id": "sha256:" + "5" * 64,
                "image_ref": "registry.example/cpa@sha256:" + "6" * 64,
                "official_asset_name": CPA_OFFICIAL_ASSET_NAME,
                "official_asset_sha256": CPA_OFFICIAL_ASSET_SHA256,
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
            "candidate_manifest": "/srv/audit-candidate-manifest.json",
            "cag_repository": "/srv/cag",
            "cag_so": f"/srv/{CAG_SO_NAME}",
            "corpus_manifest": "/srv/acquisition/corpus-manifest.json",
            "cpa_official_asset": f"/srv/{CPA_OFFICIAL_ASSET_NAME}",
            "evidence_directory": "/srv/evidence",
            "mock_source": "/srv/counted_mock.py",
            "supplemental_zip": "/srv/Codex-full.zip",
            "supplemental_zip_manifest": "/srv/supplemental-zip-manifest.json",
            "supplemental_zip_policy": "/srv/supplemental-zip-policy.json",
        },
        "policy_sha256": "b" * 64,
        "run": {
            "cold_start_count": 3,
            "platform": "linux/amd64",
            "run_id": "unit-run",
            "seed": 1205,
        },
        "schema": RUN_CONFIG_SCHEMA,
        "supplemental_zip": {
            "archive_bytes": 5830796,
            "archive_sha256": "23000a55f3922c9c2daf04e27d4bdf49d5f95109dd76ba25fa0b3f834c67ed1c",
            "manifest_sha256": "c" * 64,
            "policy_sha256": "509d0433d31717eac413594a9647a12f9bb90fe3a46a039a182a756b40ab1efb",
            "selected_entry_count": 4,
            "unique_reviewed_cases": 7,
        },
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
    value = _candidate_manifest_value(_cag_identity())
    return value, canonical_bytes(value) + b"\n"


def workload_manifest() -> tuple[dict[str, Any], bytes]:
    workloads = []
    for identifier in (
        "fixed_workload",
        "ordinary",
        "five_repository_activation",
        "public",
        LARGE_PAYLOAD_WORKLOAD,
    ):
        request = {
            "body_bytes": (
                LARGE_PAYLOAD_BYTES
                if identifier == LARGE_PAYLOAD_WORKLOAD
                else len((identifier + ":body").encode("utf-8"))
            ),
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


def _mount_backing(
    source: str,
    *,
    inode: int,
    filesystem_type: str = "ext4",
) -> dict[str, Any]:
    value = {
        "content_sha256": sha256_bytes((source + ":content").encode("utf-8")),
        "device": "8:1",
        "filesystem_type": filesystem_type,
        "kind": "file",
        "mount_flags": ["relatime", "rw"],
        "mount_options_sha256": sha256_bytes(b"fixture-mount-options"),
        "mount_root_sha256": sha256_bytes(b"fixture-mount-root"),
        "mount_source_sha256": sha256_bytes(b"fixture-mount-source"),
        "resolved_source_sha256": sha256_bytes(source.encode("utf-8")),
        "source_path_sha256": sha256_bytes(source.encode("utf-8")),
        "st_dev": 2049,
        "st_ino": inode,
        "st_mode": 0o640,
        "st_nlink": 1,
        "st_size": 4096,
        "super_flags": ["rw"],
        "super_options_sha256": sha256_bytes(b"fixture-super-options"),
    }
    value["identity_sha256"] = sha256_bytes(canonical_bytes(value))
    return value


def _mount_record(
    source: str,
    destination: str,
    *,
    inode: int,
    read_only: bool,
) -> dict[str, Any]:
    return {
        "backing": _mount_backing(source, inode=inode),
        "destination": destination,
        "driver": "",
        "mode": "ro" if read_only else "rw",
        "propagation": "rprivate",
        "read_only": read_only,
        "source_path_sha256": sha256_bytes(source.encode("utf-8")),
        "type": "bind",
    }


def _mount_projection(arm: str) -> dict[str, Any]:
    common = [
        _mount_record(
            "/srv/shared-workloads",
            "/cag/workloads",
            inode=100,
            read_only=True,
        )
    ]
    config_runtime = [
        _mount_record(
            f"/srv/{arm}-config.yaml",
            "/cag/config.yaml",
            inode=200 if arm == "cpa_only" else 201,
            read_only=True,
        )
    ]
    plugin = (
        _mount_record(
            "/srv/candidate-plugins",
            "/cag/plugins",
            inode=300,
            read_only=True,
        )
        if arm == "cpa_cag"
        else None
    )
    arm_specific = {
        "arm": arm,
        "cag_plugin_mount": plugin,
        "config_runtime_mounts": config_runtime,
    }
    return {
        "arm": arm,
        "arm_specific_sha256": sha256_bytes(canonical_bytes(arm_specific)),
        "cag_plugin_mount": plugin,
        "common_mounts": common,
        "common_sha256": sha256_bytes(canonical_bytes(common)),
        "config_runtime_mounts": config_runtime,
        "projection_boundary": MOUNT_PROJECTION_BOUNDARY,
    }


def _runtime(
    config: dict[str, Any], arm: str, ordinal: int
) -> dict[str, Any]:
    mount_projection = _mount_projection(arm)
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
        "docker_arm_specific_mount_sha256": mount_projection[
            "arm_specific_sha256"
        ],
        "docker_common_mount_sha256": mount_projection["common_sha256"],
        "docker_comparable_sha256": sha256_bytes(b"shared-docker-comparable"),
        "docker_mount_projection_sha256": sha256_bytes(
            canonical_bytes(mount_projection)
        ),
        "loaded_cag_so_sha256": config["identities"]["cag"]["so_sha256"] if arm == "cpa_cag" else None,
        "mock_container_id": "container-mock",
        "mock_image_id": config["identities"]["mock"]["image_id"],
        "mock_oom_killed": False,
        "mock_restart_count": 0,
        "mock_source_sha256": config["identities"]["mock"]["source_sha256"],
        "mount_identity_projection": mount_projection,
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
    for cell in value["large_payload_cells"]:
        cursor += timedelta(seconds=config["plan"]["warmup_seconds"])
        cell["started_at"] = _stamp(cursor)
        for sample in (
            *cell["rss_baseline_samples"],
            *cell["rss_samples"],
        ):
            sample["observed_at"] = _stamp(
                cursor + timedelta(milliseconds=float(sample["elapsed_ms"]))
            )
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
        candidate_latency = {
            "ordinary": 2.0,
            "five_repository_activation": 100.0,
            "public": 100.0,
        }[workload]
        latency = candidate_latency if arm == "cpa_cag" else 1.0
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


def _large_payload_cell(
    config: dict[str, Any],
    workload_map: dict[str, dict[str, Any]],
    *,
    arm: str,
    repetition: int,
    order_index: int,
    ordinal: int,
) -> dict[str, Any]:
    elapsed = 1.0
    peak_rss = 102.0 if arm == "cpa_only" else 105.0
    process_identity = {
        "pid": 4101 if arm == "cpa_only" else 4102,
        "start_time_ticks": 987654 + (1 if arm == "cpa_cag" else 0),
    }
    baseline_samples = [
        {
            "elapsed_ms": float(marker),
            "final_sample": False,
            "observed_at": STAMP,
            "pid": process_identity["pid"],
            "process_start_time_ticks": process_identity["start_time_ticks"],
            "rss_mib": 100.0,
        }
        for marker in range(0, 81, LARGE_PAYLOAD_RSS_SAMPLE_INTERVAL_MS)
    ]
    rss_samples = [
        {
            "elapsed_ms": float(marker),
            "final_sample": marker == 1000,
            "observed_at": STAMP,
            "pid": process_identity["pid"],
            "process_start_time_ticks": process_identity["start_time_ticks"],
            "rss_mib": peak_rss,
        }
        for marker in range(100, 1001, LARGE_PAYLOAD_RSS_SAMPLE_INTERVAL_MS)
    ]
    contract = workload_map[LARGE_PAYLOAD_WORKLOAD]
    return {
        "arm": arm,
        "completed_at": STAMP,
        "completed_requests": LARGE_PAYLOAD_REQUESTS,
        "concurrency": LARGE_PAYLOAD_CONCURRENCY,
        "elapsed_seconds": elapsed,
        "infrastructure_errors": [],
        "latency_samples_ms": [10.0] * LARGE_PAYLOAD_REQUESTS,
        "mock_counters": _mock_counters(200, LARGE_PAYLOAD_REQUESTS),
        "order_index": order_index,
        "pair_id": f"large-payload-r{repetition}",
        "payload_body_sha256": contract["requests"][0]["body_sha256"],
        "payload_size_bytes": LARGE_PAYLOAD_BYTES,
        "planned_requests": LARGE_PAYLOAD_REQUESTS,
        "process_identity": process_identity,
        "repetition": repetition,
        "request_started_elapsed_ms": 100.0,
        "request_set_sha256": contract["request_set_sha256"],
        "rss_baseline_samples": baseline_samples,
        "rss_samples": rss_samples,
        "runtime": _runtime(config, arm, ordinal),
        "started_at": STAMP,
        "successful_samples": LARGE_PAYLOAD_REQUESTS,
        "unexpected_http_errors": 0,
        "warmup_seconds": 30,
        "workload": LARGE_PAYLOAD_WORKLOAD,
    }


def measurements() -> tuple[
    dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes
]:
    config, config_raw, run, run_raw, candidate, candidate_raw, workload, workload_raw = performance_config()
    workload_map = {item["id"]: item for item in workload["workloads"]}
    paired: list[dict[str, Any]] = []
    absolute: list[dict[str, Any]] = []
    large_payload: list[dict[str, Any]] = []
    ordinal = 0
    from host_performance import paired_order, workload_paired_order

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
                for order_index, arm in enumerate(
                    workload_paired_order(1206, workload_id, concurrency, repetition)
                ):
                    ordinal += 1
                    absolute.append(
                        _cell(
                            config,
                            workload_map,
                            phase="absolute",
                            arm=arm,
                            workload=workload_id,
                            concurrency=concurrency,
                            repetition=repetition,
                            order_index=order_index,
                            ordinal=ordinal,
                        )
                    )
    for repetition in range(1, 4):
        for order_index, arm in enumerate(
            workload_paired_order(
                1206,
                LARGE_PAYLOAD_WORKLOAD,
                LARGE_PAYLOAD_CONCURRENCY,
                repetition,
            )
        ):
            ordinal += 1
            large_payload.append(
                _large_payload_cell(
                    config,
                    workload_map,
                    arm=arm,
                    repetition=repetition,
                    order_index=order_index,
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
        "large_payload_cells": large_payload,
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
