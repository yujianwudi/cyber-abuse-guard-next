#!/usr/bin/env python3
"""Fail-closed CLI validator for current-CPA corpus, config, and evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from audit_contract import (
    ContractError,
    canonical_bytes,
    load_json_bytes,
    load_json_file,
    read_regular_bytes,
    sha256_bytes,
    validate_candidate_manifest_file,
    validate_corpus_manifest,
    validate_evidence_run_config,
    validate_machine_evidence,
    validate_manifest_policy,
    validate_run_config,
    validate_supplemental_run_config_files,
)


TOOL_DIR = Path(__file__).resolve().parent


def fixed_policy() -> tuple[dict[str, Any], str]:
    # The Host-performance command has its own approved execution-closure
    # identity.  Do not execute the corpus acquisition module before that
    # command verifies its closed tool bundle.
    from acquire import validate_policy

    path = TOOL_DIR / "repository-policy.json"
    raw = read_regular_bytes(path, "fixed source policy", 2 * 1024 * 1024)
    return (
        validate_policy(
            load_json_bytes(raw, "fixed source policy"), require_approved=True
        ),
        sha256_bytes(raw),
    )


def bind_policy(manifest: dict[str, Any]) -> None:
    policy, policy_sha256 = fixed_policy()
    if manifest["policy_sha256"] != policy_sha256:
        raise ContractError("corpus policy SHA does not match this validator bundle")
    validate_manifest_policy(manifest, policy, require_approved=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    corpus = commands.add_parser("corpus", help="validate an acquired corpus manifest")
    corpus.add_argument("--manifest", type=Path, required=True)
    corpus.add_argument(
        "--corpus-root",
        type=Path,
        help="verify ephemeral text files too; omit after the runner has cleaned them",
    )
    config = commands.add_parser("run-config", help="validate a closed run config")
    config.add_argument("--config", type=Path, required=True)
    evidence = commands.add_parser("evidence", help="validate final machine evidence")
    evidence.add_argument("--manifest", type=Path, required=True)
    evidence.add_argument("--evidence", type=Path, required=True)
    evidence.add_argument("--results", type=Path, required=True)
    evidence.add_argument("--run-config", type=Path, required=True)
    performance = commands.add_parser(
        "host-performance", help="validate RT13-06 CPA-only/CPA+CAG Host evidence"
    )
    performance.add_argument("--run-config", type=Path, required=True)
    performance.add_argument("--candidate-manifest", type=Path, required=True)
    performance.add_argument("--workload-manifest", type=Path, required=True)
    performance.add_argument("--config", type=Path, required=True)
    performance.add_argument("--measurements", type=Path, required=True)
    performance.add_argument("--evidence", type=Path, required=True)
    host = commands.add_parser(
        "host-admission", help="validate Round 14 300s/3600s Host admission evidence"
    )
    host.add_argument("--evidence", type=Path, required=True)
    host.add_argument("--samples-300s", type=Path, required=True)
    host.add_argument("--samples-3600s", type=Path, required=True)
    host.add_argument("--realtime-routes", type=Path, required=True)
    host.add_argument("--expected-candidate", type=Path, required=True)
    lazy = commands.add_parser(
        "lazy-read", help="validate Round 14 lazy-read phase and request bindings"
    )
    lazy.add_argument("--phase-boundary", type=Path, required=True)
    lazy.add_argument("--runtime-read-trace", type=Path, required=True)
    lazy.add_argument("--runtime-read-summary", type=Path, required=True)
    lazy.add_argument("--manifest", type=Path, required=True)
    lazy.add_argument("--results", type=Path, required=True)
    lazy.add_argument("--supplemental-manifest", type=Path, required=True)
    lazy.add_argument("--supplemental-results", type=Path, required=True)
    csam = commands.add_parser(
        "csam-text", help="validate the synthetic Round 14 CSAM-text evidence plane"
    )
    csam.add_argument("--fixture-manifest", type=Path, required=True)
    csam.add_argument("--results", type=Path, required=True)
    csam.add_argument("--summary", type=Path, required=True)
    csam.add_argument("--privacy-cleanup", type=Path, required=True)
    csam.add_argument("--run-id")
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "corpus":
            manifest = load_json_file(args.manifest, "corpus manifest")
            validated = validate_corpus_manifest(manifest, args.corpus_root)
            bind_policy(validated)
            output: dict[str, Any] = {
                "repository_count": validated["repository_count"],
                "source_count": validated["source_count"],
                "unique_content_hashes": validated["unique_content_hashes"],
                "unique_semantic_cases": validated["unique_semantic_cases"],
                "valid": True,
            }
        elif args.command == "run-config":
            config_raw = read_regular_bytes(args.config, "run config", 2 * 1024 * 1024)
            config = validate_run_config(load_json_bytes(config_raw, "run config"))
            if config_raw != canonical_bytes(config) + b"\n":
                raise ContractError("run config is not canonical JSON with one terminal newline")
            policy, policy_sha256 = fixed_policy()
            if config["policy_sha256"] != policy_sha256:
                raise ContractError("run config policy SHA does not match this validator bundle")
            manifest_path = Path(config["paths"]["corpus_manifest"])
            manifest_raw = read_regular_bytes(
                manifest_path, "corpus manifest", 64 * 1024 * 1024
            )
            manifest = validate_corpus_manifest(
                load_json_bytes(manifest_raw, "corpus manifest")
            )
            if manifest_raw != canonical_bytes(manifest) + b"\n":
                raise ContractError(
                    "corpus manifest is not canonical JSON with one terminal newline"
                )
            if sha256_bytes(manifest_raw) != config["corpus_manifest_sha256"]:
                raise ContractError("run config corpus manifest SHA drifted")
            if manifest["policy_sha256"] != policy_sha256:
                raise ContractError("corpus candidate was not acquired with this approved policy")
            validate_manifest_policy(manifest, policy, require_approved=True)
            validate_candidate_manifest_file(config)
            validate_supplemental_run_config_files(config)
            output = {"policy_review_status": "approved", "valid": True}
        elif args.command == "evidence":
            manifest = load_json_file(args.manifest, "corpus manifest")
            bind_policy(validate_corpus_manifest(manifest))
            evidence = load_json_file(args.evidence, "machine evidence")
            if not isinstance(evidence, dict):
                raise ContractError("machine evidence must be a JSON object")
            identities = evidence.get("identities")
            if not isinstance(identities, dict):
                raise ContractError("machine evidence.identities must be a JSON object")
            from run import runner_identities

            if identities.get("runner") != runner_identities():
                raise ContractError("machine evidence runner identity does not match this bundle")
            validated = validate_machine_evidence(manifest, evidence, args.results)
            declared_manifest = args.evidence.parent / validated["corpus"]["manifest_path"]
            declared_results = args.evidence.parent / validated["transport"]["results_path"]
            declared_supplemental_manifest = (
                args.evidence.parent
                / validated["supplemental_zip_manifest"]["manifest_path"]
            )
            declared_supplemental_policy = (
                args.evidence.parent
                / validated["supplemental_zip_manifest"]["policy_path"]
            )
            declared_supplemental_results = (
                args.evidence.parent
                / validated["supplemental_zip_results"]["results_path"]
            )
            if declared_manifest.resolve(strict=True) != args.manifest.resolve(strict=True):
                raise ContractError("supplied manifest path does not match evidence.corpus.manifest_path")
            if declared_results.resolve(strict=True) != args.results.resolve(strict=True):
                raise ContractError("supplied results path does not match evidence.transport.results_path")
            for path, label in (
                (declared_supplemental_manifest, "supplemental ZIP manifest"),
                (declared_supplemental_policy, "supplemental ZIP policy"),
                (declared_supplemental_results, "supplemental ZIP results"),
            ):
                if path.resolve(strict=True).parent != args.evidence.parent.resolve(
                    strict=True
                ):
                    raise ContractError(
                        f"evidence {label} path escaped the supplied evidence directory"
                    )
            config_raw = read_regular_bytes(args.run_config, "run config", 2 * 1024 * 1024)
            config = validate_run_config(load_json_bytes(config_raw, "run config"))
            if config_raw != canonical_bytes(config) + b"\n":
                raise ContractError("run config is not canonical JSON with one terminal newline")
            validate_candidate_manifest_file(config)
            validate_supplemental_run_config_files(config)
            if Path(config["paths"]["evidence_directory"]).resolve(strict=True) != args.evidence.parent.resolve(strict=True):
                raise ContractError("run config evidence directory does not match the supplied evidence")
            validate_evidence_run_config(validated, config, config_raw)
            output = {
                "cold_start_count": validated["run"]["cold_start_count"],
                "third_party_code_executions": validated["third_party_code_executions"],
                "supplemental_executions": validated["supplemental_zip_results"][
                    "supplemental_executions"
                ],
                "transport_executions": validated["transport"]["transport_executions"],
                "valid": True,
            }
        elif args.command == "host-admission":
            import host_admission as host

            evidence_raw = read_regular_bytes(
                args.evidence, "Host admission evidence", host.MAX_EVIDENCE_BYTES
            )
            expected_raw = read_regular_bytes(
                args.expected_candidate, "trusted Host candidate identity", 2 * 1024 * 1024
            )
            expected_candidate = load_json_bytes(
                expected_raw, "trusted Host candidate identity"
            )
            if expected_raw != canonical_bytes(expected_candidate) + b"\n":
                raise ContractError(
                    "trusted Host candidate identity is not canonical JSON with one terminal newline"
                )
            validated_host = host.parse_host_admission(
                evidence_raw,
                read_regular_bytes(
                    args.samples_300s, "Host admission 300-second samples",
                    301 * host.MAX_SAMPLE_LINE_BYTES,
                ),
                read_regular_bytes(
                    args.samples_3600s, "Host admission 3600-second samples",
                    3_601 * host.MAX_SAMPLE_LINE_BYTES,
                ),
                read_regular_bytes(
                    args.realtime_routes, "Host admission Realtime routes",
                    len(host.REALTIME_ROUTE_CONTRACT) * host.MAX_SAMPLE_LINE_BYTES,
                ),
                expected_candidate,
            )
            output = {
                "host_300s_samples": validated_host["windows"][0]["sample_count"],
                "host_3600s_samples": validated_host["windows"][1]["sample_count"],
                "realtime_routes": validated_host["tail_verification"]["realtime"]["route_count"],
                "status": validated_host["status"],
                "valid": True,
            }
        elif args.command == "lazy-read":
            from second_machine_release_admission import (
                validate_lazy_read_bindings,
                validate_lazy_read_evidence,
            )

            phase = load_json_file(args.phase_boundary, "lazy-read phase boundary")
            summary = load_json_file(args.runtime_read_summary, "lazy-read runtime summary")
            trace_raw = read_regular_bytes(
                args.runtime_read_trace,
                "lazy-read runtime trace",
                64 * 1024 * 1024,
                require_single_link=True,
            )
            projection = validate_lazy_read_evidence(phase, trace_raw, summary)
            manifest = load_json_file(args.manifest, "lazy-read corpus manifest")
            supplemental_manifest = load_json_file(
                args.supplemental_manifest, "lazy-read supplemental manifest"
            )
            results_raw = read_regular_bytes(
                args.results, "lazy-read transport results", 128 * 1024 * 1024,
                require_single_link=True,
            )
            supplemental_results_raw = read_regular_bytes(
                args.supplemental_results,
                "lazy-read supplemental results",
                128 * 1024 * 1024,
                require_single_link=True,
            )
            validate_lazy_read_bindings(
                trace_raw,
                manifest,
                results_raw,
                supplemental_manifest,
                supplemental_results_raw,
            )
            output = {**projection, "bindings": "PASS", "valid": True}
        elif args.command == "csam-text":
            from second_machine_release_admission import validate_csam_text_evidence

            fixture = load_json_file(args.fixture_manifest, "CSAM text fixture manifest")
            results = load_json_file(args.results, "CSAM text results")
            summary = load_json_file(args.summary, "CSAM text summary")
            cleanup = load_json_file(args.privacy_cleanup, "CSAM text privacy cleanup")
            projection = validate_csam_text_evidence(
                fixture,
                results,
                summary,
                cleanup,
                expected_run_id=args.run_id,
            )
            output = {**projection, "valid": True}
        else:
            from host_performance import (
                validate_config as validate_performance_config,
                validate_evidence_bundle,
                validate_measurements,
                validate_workload_manifest,
            )

            run_config_raw = read_regular_bytes(
                args.run_config, "run config", 2 * 1024 * 1024
            )
            run_config = validate_run_config(
                load_json_bytes(run_config_raw, "run config")
            )
            if run_config_raw != canonical_bytes(run_config) + b"\n":
                raise ContractError(
                    "run config is not canonical JSON with one terminal newline"
                )
            candidate, candidate_raw = validate_candidate_manifest_file(run_config)
            if args.candidate_manifest.resolve(strict=True) != Path(
                run_config["paths"]["candidate_manifest"]
            ).resolve(strict=True):
                raise ContractError(
                    "supplied candidate manifest path does not match the run config"
                )
            workload_raw = read_regular_bytes(
                args.workload_manifest,
                "performance workload manifest",
                2 * 1024 * 1024,
            )
            workload = validate_workload_manifest(
                load_json_bytes(workload_raw, "performance workload manifest")
            )
            if workload_raw != canonical_bytes(workload) + b"\n":
                raise ContractError(
                    "performance workload manifest is not canonical JSON with one terminal newline"
                )
            performance_config_raw = read_regular_bytes(
                args.config, "host performance config", 2 * 1024 * 1024
            )
            performance_config = validate_performance_config(
                load_json_bytes(performance_config_raw, "host performance config"),
                run_config,
                run_config_raw,
                candidate,
                candidate_raw,
                workload_raw,
            )
            if performance_config_raw != canonical_bytes(performance_config) + b"\n":
                raise ContractError(
                    "host performance config is not canonical JSON with one terminal newline"
                )
            measurements_raw = read_regular_bytes(
                args.measurements, "host performance measurements", 128 * 1024 * 1024
            )
            measurements = load_json_bytes(
                measurements_raw,
                "host performance measurements",
                128 * 1024 * 1024,
            )
            if not isinstance(measurements, dict):
                raise ContractError(
                    "host performance measurements must be a JSON object"
                )
            if measurements_raw != canonical_bytes(measurements) + b"\n":
                raise ContractError(
                    "host performance measurements are not canonical JSON with one terminal newline"
                )
            validated_measurements, summaries, baseline, extra = validate_measurements(
                measurements,
                measurements_raw,
                performance_config,
                performance_config_raw,
                workload,
            )
            performance_evidence_raw = read_regular_bytes(
                args.evidence, "host performance evidence", 8 * 1024 * 1024
            )
            performance_evidence = load_json_bytes(
                performance_evidence_raw, "host performance evidence"
            )
            if not isinstance(performance_evidence, dict):
                raise ContractError("host performance evidence must be a JSON object")
            if performance_evidence_raw != canonical_bytes(performance_evidence) + b"\n":
                raise ContractError(
                    "host performance evidence is not canonical JSON with one terminal newline"
                )
            validated_performance = validate_evidence_bundle(
                performance_evidence,
                performance_config,
                performance_config_raw,
                validated_measurements,
                measurements_raw,
                summaries,
                baseline,
                extra,
                require_pass=True,
            )
            output = {
                "audit_queue_peak_ratio": validated_performance["metrics"][
                    "audit_queue_peak_ratio"
                ],
                "host_throughput_vs_cpa_only": validated_performance["metrics"][
                    "host_throughput_vs_cpa_only"
                ],
                "status": validated_performance["status"],
                "valid": True,
                "warm_rss_growth_60m_mib": validated_performance["metrics"][
                    "warm_rss_growth_60m_mib"
                ],
            }
        print(json.dumps(output, sort_keys=True))
        return 0
    except (ContractError, OSError) as exc:
        print(f"VALIDATION FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
