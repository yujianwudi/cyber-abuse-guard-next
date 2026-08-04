#!/usr/bin/env python3
"""Create a canonical, closed current-CPA run config from local identities."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from acquire import validate_policy
from audit_contract import (
    CPA_COMMIT,
    CPA_TAG,
    MOCK_CONTRACT,
    RUN_CONFIG_SCHEMA,
    ContractError,
    canonical_bytes,
    load_json_bytes,
    read_regular_bytes,
    sha256_bytes,
    sha256_file,
    validate_corpus_manifest,
    validate_manifest_policy,
    validate_run_config,
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
            "--untracked-files=no",
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
        raise RuntimeError("CAG repository has tracked working-tree drift")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--seed", type=int, default=1205)
    parser.add_argument("--cold-start-count", type=int, default=3)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--cag-repository", type=Path, required=True)
    parser.add_argument("--cag-so", type=Path, required=True)
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
        cag_repository = args.cag_repository.resolve(strict=True)
        require_git_clean(cag_repository)
        cag_so = args.cag_so.resolve(strict=True)
        asset = args.cpa_official_asset.resolve(strict=True)
        if sha256_file(asset) != args.cpa_official_asset_sha256:
            raise RuntimeError("CPA official asset does not match the published SHA-256")
        evidence = args.evidence_directory.resolve(strict=False)
        mock_source = ROOT / "counted_mock.py"
        config = {
            "corpus_manifest_sha256": sha256_file(manifest),
            "identities": {
                "cag": {
                    "commit": git_id(cag_repository, "HEAD^{commit}"),
                    "so_sha256": sha256_file(cag_so),
                    "tree": git_id(cag_repository, "HEAD^{tree}"),
                },
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
                "cag_repository": str(cag_repository),
                "cag_so": str(cag_so),
                "corpus_manifest": str(manifest),
                "cpa_official_asset": str(asset),
                "evidence_directory": str(evidence),
                "mock_source": str(mock_source),
            },
            "policy_sha256": policy_sha256,
            "run": {
                "cold_start_count": args.cold_start_count,
                "platform": "linux/amd64",
                "run_id": args.run_id,
                "seed": args.seed,
            },
            "schema": RUN_CONFIG_SCHEMA,
        }
        validate_run_config(config)
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
