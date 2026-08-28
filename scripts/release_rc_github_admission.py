#!/usr/bin/env python3
"""Validate fixtureable GitHub API identities for the fixed v1.0.0-rc.3 lane."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, NoReturn, Sequence


REPOSITORY = "yujianwudi/cyber-abuse-guard-next"
CANDIDATE_NAME = "cyber-abuse-guard-linux-amd64-audit-candidate"
SECOND_MACHINE_TAG = "v1.0.0-rc.3-second-machine-admission"
SECOND_MACHINE_ASSET_NAME = "second-machine-release-admission.json"
MAX_CANDIDATE_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_SECOND_MACHINE_REPORT_BYTES = 8 * 1024 * 1024
MAX_CLOCK_SKEW = timedelta(minutes=5)
FIXTURE_NOW_ENV = "CAG_RC_GITHUB_ADMISSION_ALLOW_FIXTURE_NOW"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class AdmissionError(ValueError):
    pass


def fail(message: str) -> NoReturn:
    raise AdmissionError(message)


def positive(value: Any, label: str, maximum: int | None = None) -> int:
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        fail(f"{label} must be a positive bounded integer")
    return value


def string(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        fail(f"{label} must be a non-empty string")
    return value


def timestamp(value: Any, label: str) -> datetime:
    value = string(value, label)
    if not value.endswith("Z"):
        fail(f"{label} must be UTC Z")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(f"{label} is invalid")
    return result


def load(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{label} cannot be read as JSON: {type(exc).__name__}")


def flatten_artifacts(value: Any) -> list[Mapping[str, Any]]:
    pages = value if type(value) is list else [value]
    artifacts: list[Mapping[str, Any]] = []
    for index, page in enumerate(pages):
        if type(page) is not dict or type(page.get("artifacts")) is not list:
            fail(f"candidate artifact page {index} is invalid")
        for artifact in page["artifacts"]:
            if type(artifact) is not dict:
                fail("candidate artifact entry is not an object")
            artifacts.append(artifact)
    return artifacts


def flatten_release_assets(value: Any) -> list[Mapping[str, Any]]:
    if type(value) is list and all(type(item) is dict for item in value):
        pages = [value]
    else:
        pages = value if type(value) is list else [value]
    assets: list[Mapping[str, Any]] = []
    for index, page in enumerate(pages):
        if type(page) is not list:
            fail(f"release asset page {index} is invalid")
        for asset in page:
            if type(asset) is not dict:
                fail("release asset entry is not an object")
            assets.append(asset)
    return assets


def validate_candidate(
    value: Any,
    *,
    repository: str,
    commit: str,
    run_id: int,
    now: datetime,
) -> dict[str, Any]:
    matches = [item for item in flatten_artifacts(value) if item.get("name") == CANDIDATE_NAME]
    if len(matches) != 1:
        fail("CI run must contain exactly one audit-candidate artifact by exact name")
    artifact = matches[0]
    artifact_id = positive(artifact.get("id"), "candidate artifact.id")
    size = positive(artifact.get("size_in_bytes"), "candidate artifact.size_in_bytes", MAX_CANDIDATE_ARTIFACT_BYTES)
    digest = string(artifact.get("digest"), "candidate artifact.digest")
    if DIGEST.fullmatch(digest) is None:
        fail("candidate artifact.digest is not sha256:<lowercase hex>")
    if artifact.get("expired") is not False:
        fail("candidate artifact is expired or has no explicit non-expired state")
    created = timestamp(artifact.get("created_at"), "candidate artifact.created_at")
    expires = timestamp(artifact.get("expires_at"), "candidate artifact.expires_at")
    if not (created <= now + MAX_CLOCK_SKEW and now <= expires and expires > created):
        fail("candidate artifact is outside its GitHub retention interval")
    workflow = artifact.get("workflow_run")
    if type(workflow) is not dict or workflow.get("id") != run_id or workflow.get("head_sha") != commit:
        fail("candidate artifact is not bound to the admitted CI run/commit")
    expected_url = f"https://api.github.com/repos/{repository}/actions/artifacts/{artifact_id}"
    if artifact.get("url") != expected_url:
        fail("candidate artifact API URL is outside the canonical repository")
    archive_url = string(artifact.get("archive_download_url"), "candidate artifact.archive_download_url")
    if archive_url != expected_url + "/zip":
        fail("candidate artifact archive URL is not the exact API asset")
    return {"digest": digest, "expires_at": artifact["expires_at"], "id": artifact_id, "size": size}


def validate_second_machine(
    release: Any,
    release_assets: Any,
    asset: Any,
    *,
    repository: str,
    commit: str,
    release_id: int,
    asset_id: int,
    asset_sha256: str,
    now: datetime,
) -> dict[str, Any]:
    if type(release) is not dict:
        fail("second-machine release response is not an object")
    if release.get("id") != release_id or release.get("draft") is not True:
        fail("second-machine staging release ID/draft state is invalid")
    if release.get("tag_name") != SECOND_MACHINE_TAG or release.get("target_commitish") != commit:
        fail("second-machine staging release tag/target_commitish is not the protected commit")
    if release.get("published_at") is not None:
        fail("second-machine staging release has already been published")
    release_url = f"https://api.github.com/repos/{repository}/releases/{release_id}"
    if release.get("url") != release_url or release.get("assets_url") != release_url + "/assets":
        fail("second-machine staging release URLs are outside the canonical repository")
    created = timestamp(release.get("created_at"), "second-machine release.created_at")
    if created > now + MAX_CLOCK_SKEW:
        fail("second-machine staging release creation time is in the future")

    members = [item for item in flatten_release_assets(release_assets) if item.get("name") == SECOND_MACHINE_ASSET_NAME]
    if len(members) != 1 or members[0].get("id") != asset_id:
        fail("second-machine report asset is not the unique fixed-name member of the draft release")
    if type(asset) is not dict or asset.get("id") != asset_id:
        fail("second-machine report asset detail ID is invalid")
    if asset != members[0]:
        fail("second-machine report asset detail differs from the release membership record")
    if asset.get("name") != SECOND_MACHINE_ASSET_NAME or asset.get("state") != "uploaded":
        fail("second-machine report asset name/upload state is invalid")
    size = positive(asset.get("size"), "second-machine asset.size", MAX_SECOND_MACHINE_REPORT_BYTES)
    digest = string(asset.get("digest"), "second-machine asset.digest")
    expected_digest = "sha256:" + asset_sha256
    if digest != expected_digest:
        fail("second-machine report API digest differs from the dispatch SHA-256")
    asset_url = f"https://api.github.com/repos/{repository}/releases/assets/{asset_id}"
    if asset.get("url") != asset_url:
        fail("second-machine report asset URL is outside the canonical repository")
    asset_created = timestamp(asset.get("created_at"), "second-machine asset.created_at")
    asset_updated = timestamp(asset.get("updated_at"), "second-machine asset.updated_at")
    if not (created <= asset_created <= asset_updated <= now + MAX_CLOCK_SKEW):
        fail("second-machine report asset timestamps do not belong to the staging release interval")
    return {"digest": digest, "id": asset_id, "release_id": release_id, "size": size}


def validate(
    *,
    candidate_artifacts: Any,
    release: Any,
    release_assets: Any,
    asset: Any,
    repository: str,
    commit: str,
    ci_run_id: int,
    release_id: int,
    asset_id: int,
    asset_sha256: str,
    now: datetime,
) -> dict[str, Any]:
    if repository != REPOSITORY:
        fail("release admission repository is not canonical")
    if HEX40.fullmatch(commit) is None:
        fail("release admission commit must be lowercase 40-hex")
    positive(ci_run_id, "CI run ID")
    positive(release_id, "second-machine release ID")
    positive(asset_id, "second-machine asset ID")
    if HEX64.fullmatch(asset_sha256) is None:
        fail("second-machine asset SHA-256 must be lowercase 64-hex")
    candidate = validate_candidate(candidate_artifacts, repository=repository, commit=commit, run_id=ci_run_id, now=now)
    second = validate_second_machine(
        release,
        release_assets,
        asset,
        repository=repository,
        commit=commit,
        release_id=release_id,
        asset_id=asset_id,
        asset_sha256=asset_sha256,
        now=now,
    )
    return {
        "candidate_artifact_digest": candidate["digest"],
        "candidate_artifact_expires_at": candidate["expires_at"],
        "candidate_artifact_id": candidate["id"],
        "candidate_artifact_size": candidate["size"],
        "second_machine_asset_digest": second["digest"],
        "second_machine_asset_id": second["id"],
        "second_machine_asset_size": second["size"],
        "second_machine_release_id": second["release_id"],
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--candidate-artifacts", type=Path, required=True)
    result.add_argument("--second-machine-release", type=Path, required=True)
    result.add_argument("--second-machine-release-assets", type=Path, required=True)
    result.add_argument("--second-machine-asset", type=Path, required=True)
    result.add_argument("--repository", default=REPOSITORY)
    result.add_argument("--commit", required=True)
    result.add_argument("--ci-run-id", type=int, required=True)
    result.add_argument("--second-machine-release-id", type=int, required=True)
    result.add_argument("--second-machine-asset-id", type=int, required=True)
    result.add_argument("--second-machine-asset-sha256", default="")
    result.add_argument("--now", help="fixture-only UTC time; workflow omits this")
    result.add_argument("--github-output", type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.now and os.environ.get(FIXTURE_NOW_ENV) != "1":
            fail(f"--now requires fixture-only opt-in {FIXTURE_NOW_ENV}=1")
        now = timestamp(args.now, "--now") if args.now else datetime.now(timezone.utc)
        output = validate(
            candidate_artifacts=load(args.candidate_artifacts, "candidate artifact response"),
            release=load(args.second_machine_release, "second-machine release response"),
            release_assets=load(
                args.second_machine_release_assets,
                "second-machine release assets response",
            ),
            asset=load(args.second_machine_asset, "second-machine asset response"),
            repository=args.repository,
            commit=args.commit,
            ci_run_id=args.ci_run_id,
            release_id=args.second_machine_release_id,
            asset_id=args.second_machine_asset_id,
            asset_sha256=args.second_machine_asset_sha256,
            now=now,
        )
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8", newline="\n") as handle:
                for key, value in output.items():
                    handle.write(f"{key}={value}\n")
        print(json.dumps({**output, "valid": True}, sort_keys=True))
        return 0
    except (AdmissionError, OSError, ValueError) as exc:
        print(f"RC GITHUB ADMISSION FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
