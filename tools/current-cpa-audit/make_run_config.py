#!/usr/bin/env python3
"""Create a canonical, closed current-CPA run config from local identities."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

from acquire import validate_policy
from audit_contract import (
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CPA_COMMIT,
    CPA_TAG,
    MOCK_CONTRACT,
    RUN_CONFIG_SCHEMA,
    SUPPLEMENTAL_ZIP_LIMITS,
    ContractError,
    candidate_identity,
    canonical_bytes,
    load_json_bytes,
    read_regular_bytes,
    read_candidate_manifest,
    regular_file_info,
    sha256_bytes,
    sha256_file,
    validate_corpus_manifest,
    validate_manifest_policy,
    validate_run_config,
    validate_supplemental_manifest,
    validate_supplemental_policy,
    validate_supplemental_run_config_files,
)


ROOT = Path(__file__).resolve().parent


def git_id(repository: Path, expression: str) -> str:
    environment = os.environ.copy()
    environment.update({"GIT_OPTIONAL_LOCKS": "0", "HTTP_PROXY": "", "HTTPS_PROXY": ""})
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(repository),
            "rev-parse",
            expression,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        env=environment,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cannot read CAG Git identity for {expression}")
    return result.stdout.strip().lower()


def require_git_clean(repository: Path) -> None:
    environment = os.environ.copy()
    environment.update({"GIT_OPTIONAL_LOCKS": "0", "HTTP_PROXY": "", "HTTPS_PROXY": ""})
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(repository),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        env=environment,
    )
    if result.returncode != 0 or result.stdout:
        raise RuntimeError("CAG repository has tracked or untracked working-tree drift")


def validated_cag_candidate(
    repository: Path, cag_so: Path, candidate_manifest: Path
) -> tuple[dict[str, str], dict[str, Any], bytes]:
    """Bind local CAG bytes to one exact, clean CI audit candidate."""

    require_git_clean(repository)
    regular_file_info(cag_so, "selected CAG SO", require_single_link=True)
    identity = {
        "commit": git_id(repository, "HEAD^{commit}"),
        "so_name": CAG_SO_NAME,
        "so_sha256": sha256_file(cag_so, require_single_link=True),
        "source_version": CAG_SOURCE_VERSION,
        "tree": git_id(repository, "HEAD^{tree}"),
    }
    candidate, candidate_raw = read_candidate_manifest(candidate_manifest, identity)
    artifact_name = f"cyber-abuse-guard-v{candidate['version']}.so"
    if cag_so.name != artifact_name:
        raise RuntimeError(
            "selected CAG SO filename does not match the CI audit candidate artifact_name"
        )
    if candidate_manifest.parent != cag_so.parent:
        raise RuntimeError(
            "candidate manifest and selected CAG SO must share one artifact directory"
        )
    return identity, candidate, candidate_raw


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--seed", type=int, default=1205)
    parser.add_argument("--cold-start-count", type=int, default=3)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--supplemental-archive",
        dest="supplemental_zip",
        type=Path,
        required=True,
        help="reviewed supplemental ZIP archive; members remain memory-only",
    )
    parser.add_argument("--supplemental-zip-policy", type=Path, required=True)
    parser.add_argument("--supplemental-zip-manifest", type=Path, required=True)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--cag-repository", type=Path, required=True)
    parser.add_argument("--cag-so", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument(
        "--candidate-artifact-id",
        required=True,
        help="post-upload GitHub artifact-id admission value",
    )
    parser.add_argument(
        "--candidate-artifact-name",
        required=True,
        help="post-upload GitHub artifact name",
    )
    parser.add_argument(
        "--candidate-artifact-digest",
        required=True,
        help="post-upload GitHub artifact-digest admission value (sha256:<64-hex>)",
    )
    parser.add_argument("--cpa-official-asset", type=Path, required=True)
    parser.add_argument(
        "--cpa-official-asset-sha256",
        required=True,
        help="published official SHA-256, not a value derived from this local copy",
    )
    parser.add_argument("--cpa-binary-path", required=True)
    parser.add_argument("--cpa-binary-sha256", required=True)
    parser.add_argument("--cpa-image-ref", required=True, help="exact name@sha256 RepoDigest")
    parser.add_argument("--cpa-image-id", required=True)
    parser.add_argument("--mock-image-ref", required=True, help="exact name@sha256 RepoDigest")
    parser.add_argument("--mock-image-id", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        output = args.output.resolve(strict=False)
        if output.exists() or output.is_symlink():
            raise RuntimeError("output config must be a new path")
        manifest = args.manifest.resolve(strict=True)
        manifest_raw = read_regular_bytes(manifest, "corpus manifest", 64 * 1024 * 1024)
        manifest_value = validate_corpus_manifest(
            load_json_bytes(manifest_raw, "corpus manifest"), manifest.parent
        )
        if manifest_raw != canonical_bytes(manifest_value) + b"\n":
            raise RuntimeError("corpus manifest is not canonical JSON with one terminal newline")
        policy = ROOT / "repository-policy.json"
        policy_raw = read_regular_bytes(policy, "fixed source policy", 2 * 1024 * 1024)
        policy_value = validate_policy(
            load_json_bytes(policy_raw, "fixed source policy"), require_approved=True
        )
        policy_sha256 = sha256_bytes(policy_raw)
        if manifest_value["policy_sha256"] != policy_sha256:
            raise RuntimeError("corpus candidate was not acquired with this approved policy")
        validate_manifest_policy(manifest_value, policy_value, require_approved=True)
        for path, label in (
            (args.supplemental_zip, "supplemental ZIP archive input"),
            (args.supplemental_zip_policy, "supplemental ZIP policy input"),
            (args.supplemental_zip_manifest, "supplemental ZIP manifest input"),
        ):
            regular_file_info(path, label, require_single_link=True)
        supplemental_archive = args.supplemental_zip.resolve(strict=True)
        supplemental_policy = args.supplemental_zip_policy.resolve(strict=True)
        supplemental_manifest = args.supplemental_zip_manifest.resolve(strict=True)
        for path, label in (
            (supplemental_archive, "supplemental ZIP archive"),
            (supplemental_policy, "supplemental ZIP policy"),
            (supplemental_manifest, "supplemental ZIP manifest"),
        ):
            regular_file_info(path, label, require_single_link=True)
        supplemental_policy_raw = read_regular_bytes(
            supplemental_policy,
            "supplemental ZIP policy",
            2 * 1024 * 1024,
            require_single_link=True,
        )
        supplemental_policy_value = validate_supplemental_policy(
            load_json_bytes(supplemental_policy_raw, "supplemental ZIP policy"),
            require_approved=True,
        )
        supplemental_policy_sha256 = sha256_bytes(supplemental_policy_raw)
        supplemental_manifest_raw = read_regular_bytes(
            supplemental_manifest,
            "supplemental ZIP manifest",
            8 * 1024 * 1024,
            require_single_link=True,
        )
        supplemental_manifest_value = validate_supplemental_manifest(
            load_json_bytes(supplemental_manifest_raw, "supplemental ZIP manifest"),
            supplemental_policy_value,
            policy_sha256=supplemental_policy_sha256,
        )
        if supplemental_manifest_raw != canonical_bytes(supplemental_manifest_value) + b"\n":
            raise RuntimeError(
                "supplemental ZIP manifest is not canonical JSON with one terminal newline"
            )
        supplemental_archive_info = regular_file_info(
            supplemental_archive,
            "supplemental ZIP archive",
            require_single_link=True,
        )
        supplemental_archive_sha256 = sha256_file(
            supplemental_archive,
            SUPPLEMENTAL_ZIP_LIMITS["max_archive_bytes"],
            require_single_link=True,
        )
        if (
            supplemental_archive_info.st_size
            != supplemental_manifest_value["archive"]["bytes"]
            or supplemental_archive_sha256
            != supplemental_manifest_value["archive"]["sha256"]
        ):
            raise RuntimeError(
                "supplemental ZIP archive does not match the supplied validated manifest"
            )
        cag_repository = args.cag_repository.resolve(strict=True)
        cag_so = args.cag_so.resolve(strict=True)
        candidate_manifest = args.candidate_manifest.resolve(strict=True)
        cag_identity, candidate_value, candidate_raw = validated_cag_candidate(
            cag_repository, cag_so, candidate_manifest
        )
        sealed_candidate_identity = candidate_identity(
            candidate_value,
            candidate_raw,
            artifact_id=args.candidate_artifact_id,
            artifact_name=args.candidate_artifact_name,
            artifact_digest=args.candidate_artifact_digest,
        )
        asset = args.cpa_official_asset.resolve(strict=True)
        if sha256_file(asset) != args.cpa_official_asset_sha256:
            raise RuntimeError("CPA official asset does not match the published SHA-256")
        evidence = args.evidence_directory.resolve(strict=False)
        mock_source = ROOT / "counted_mock.py"
        config = {
            "corpus_manifest_sha256": sha256_file(manifest),
            "identities": {
                "candidate": sealed_candidate_identity,
                "cag": cag_identity,
                "cpa": {
                    "binary_path": args.cpa_binary_path,
                    "binary_sha256": args.cpa_binary_sha256,
                    "commit": CPA_COMMIT,
                    "image_id": args.cpa_image_id,
                    "image_ref": args.cpa_image_ref,
                    "official_asset_name": asset.name,
                    "official_asset_sha256": args.cpa_official_asset_sha256,
                    "repo_digest": args.cpa_image_ref,
                    "tag": CPA_TAG,
                },
                "mock": {
                    "contract": MOCK_CONTRACT,
                    "image_id": args.mock_image_id,
                    "image_ref": args.mock_image_ref,
                    "repo_digest": args.mock_image_ref,
                    "source_sha256": sha256_file(mock_source),
                },
            },
            "paths": {
                "candidate_manifest": str(candidate_manifest),
                "cag_repository": str(cag_repository),
                "cag_so": str(cag_so),
                "corpus_manifest": str(manifest),
                "cpa_official_asset": str(asset),
                "evidence_directory": str(evidence),
                "mock_source": str(mock_source),
                "supplemental_zip": str(supplemental_archive),
                "supplemental_zip_manifest": str(supplemental_manifest),
                "supplemental_zip_policy": str(supplemental_policy),
            },
            "policy_sha256": policy_sha256,
            "run": {
                "cold_start_count": args.cold_start_count,
                "platform": "linux/amd64",
                "run_id": args.run_id,
                "seed": args.seed,
            },
            "schema": RUN_CONFIG_SCHEMA,
            "supplemental_zip": {
                "archive_bytes": supplemental_archive_info.st_size,
                "archive_sha256": supplemental_archive_sha256,
                "manifest_sha256": sha256_bytes(supplemental_manifest_raw),
                "policy_sha256": supplemental_policy_sha256,
                "selected_entry_count": supplemental_manifest_value[
                    "selected_entry_count"
                ],
                "unique_reviewed_cases": supplemental_manifest_value[
                    "unique_reviewed_cases"
                ],
            },
        }
        validate_run_config(config)
        validate_supplemental_run_config_files(config)
        raw = canonical_bytes(config) + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(output, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            output.unlink(missing_ok=True)
            raise
        os.chmod(output, 0o600)
        print(f"config={output} sha256={sha256_bytes(raw)}")
        return 0
    except (ContractError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"CONFIG CREATION FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
