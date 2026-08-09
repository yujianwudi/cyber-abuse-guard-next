#!/usr/bin/env python3
"""Fixture tests for release_rc_github_admission.py; no network is used."""

from __future__ import annotations

import copy
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from release_rc_github_admission import (  # noqa: E402
    AdmissionError,
    CANDIDATE_NAME,
    SECOND_MACHINE_ASSET_NAME,
    SECOND_MACHINE_TAG,
    validate,
)


NOW = datetime(2026, 8, 9, 4, 0, 0, tzinfo=timezone.utc)
COMMIT = "1" * 40
REPORT_SHA = "2" * 64
REPOSITORY = "yujianwudi/cyber-abuse-guard-next"
CI_RUN_ID = 1001
RELEASE_ID = 2002
ASSET_ID = 3003


def fixture() -> dict[str, object]:
    artifact_url = f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/4004"
    candidate = {
        "artifacts": [
            {
                "archive_download_url": artifact_url + "/zip",
                "created_at": "2026-08-09T01:00:00Z",
                "digest": "sha256:" + "3" * 64,
                "expired": False,
                "expires_at": "2026-08-23T01:00:00Z",
                "id": 4004,
                "name": CANDIDATE_NAME,
                "size_in_bytes": 123456,
                "url": artifact_url,
                "workflow_run": {"head_sha": COMMIT, "id": CI_RUN_ID},
            }
        ],
        "total_count": 1,
    }
    release_url = f"https://api.github.com/repos/{REPOSITORY}/releases/{RELEASE_ID}"
    release = {
        "assets_url": release_url + "/assets",
        "created_at": "2026-08-09T02:00:00Z",
        "draft": True,
        "id": RELEASE_ID,
        "published_at": None,
        "tag_name": SECOND_MACHINE_TAG,
        "target_commitish": COMMIT,
        "url": release_url,
    }
    asset = {
        "created_at": "2026-08-09T02:30:00Z",
        "digest": "sha256:" + REPORT_SHA,
        "id": ASSET_ID,
        "name": SECOND_MACHINE_ASSET_NAME,
        "size": 654321,
        "state": "uploaded",
        "updated_at": "2026-08-09T02:31:00Z",
        "url": f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{ASSET_ID}",
    }
    return {
        "candidate_artifacts": candidate,
        "release": release,
        "release_assets": [copy.deepcopy(asset)],
        "asset": asset,
        "repository": REPOSITORY,
        "commit": COMMIT,
        "ci_run_id": CI_RUN_ID,
        "release_id": RELEASE_ID,
        "asset_id": ASSET_ID,
        "asset_sha256": REPORT_SHA,
        "now": NOW,
    }


class GitHubAdmissionTests(unittest.TestCase):
    def test_accepts_exact_unique_live_coordinates(self) -> None:
        result = validate(**fixture())
        self.assertEqual(result["candidate_artifact_id"], 4004)
        self.assertEqual(result["candidate_artifact_digest"], "sha256:" + "3" * 64)
        self.assertEqual(result["second_machine_release_id"], RELEASE_ID)
        self.assertEqual(result["second_machine_asset_digest"], "sha256:" + REPORT_SHA)

    def assert_rejected(self, mutate) -> None:  # type: ignore[no-untyped-def]
        value = fixture()
        mutate(value)
        with self.assertRaises(AdmissionError):
            validate(**value)

    def test_rejects_wrong_release_id(self) -> None:
        self.assert_rejected(lambda value: value["release"].__setitem__("id", RELEASE_ID + 1))  # type: ignore[union-attr]

    def test_rejects_non_draft_or_wrong_target(self) -> None:
        self.assert_rejected(lambda value: value["release"].__setitem__("draft", False))  # type: ignore[union-attr]
        self.assert_rejected(lambda value: value["release"].__setitem__("target_commitish", "9" * 40))  # type: ignore[union-attr]

    def test_rejects_wrong_fixed_staging_tag(self) -> None:
        self.assert_rejected(lambda value: value["release"].__setitem__("tag_name", "untrusted"))  # type: ignore[union-attr]

    def test_rejects_asset_not_in_release(self) -> None:
        self.assert_rejected(lambda value: value.__setitem__("release_assets", []))

    def test_rejects_wrong_asset_id_or_name(self) -> None:
        self.assert_rejected(lambda value: value["asset"].__setitem__("id", ASSET_ID + 1))  # type: ignore[union-attr]
        self.assert_rejected(lambda value: value["asset"].__setitem__("name", "report.json"))  # type: ignore[union-attr]

    def test_rejects_asset_digest_or_upload_state_drift(self) -> None:
        def digest(value) -> None:  # type: ignore[no-untyped-def]
            value["asset"]["digest"] = "sha256:" + "8" * 64
            value["release_assets"][0]["digest"] = "sha256:" + "8" * 64

        def state(value) -> None:  # type: ignore[no-untyped-def]
            value["asset"]["state"] = "new"
            value["release_assets"][0]["state"] = "new"

        self.assert_rejected(digest)
        self.assert_rejected(state)
        self.assert_rejected(lambda value: value.__setitem__("asset_sha256", "9" * 64))

    def test_rejects_expired_candidate_artifact(self) -> None:
        self.assert_rejected(lambda value: value["candidate_artifacts"]["artifacts"][0].__setitem__("expired", True))  # type: ignore[index,union-attr]

    def test_rejects_candidate_outside_retention_window(self) -> None:
        self.assert_rejected(lambda value: value["candidate_artifacts"]["artifacts"][0].__setitem__("expires_at", "2026-08-09T03:59:59Z"))  # type: ignore[index,union-attr]

    def test_rejects_duplicate_candidate_artifact(self) -> None:
        def mutate(value) -> None:  # type: ignore[no-untyped-def]
            value["candidate_artifacts"]["artifacts"].append(
                copy.deepcopy(value["candidate_artifacts"]["artifacts"][0])
            )

        self.assert_rejected(mutate)

    def test_rejects_candidate_wrong_run_commit_digest_or_size(self) -> None:
        self.assert_rejected(lambda value: value["candidate_artifacts"]["artifacts"][0]["workflow_run"].__setitem__("id", CI_RUN_ID + 1))  # type: ignore[index,union-attr]
        self.assert_rejected(lambda value: value["candidate_artifacts"]["artifacts"][0]["workflow_run"].__setitem__("head_sha", "8" * 40))  # type: ignore[index,union-attr]
        self.assert_rejected(lambda value: value["candidate_artifacts"]["artifacts"][0].__setitem__("digest", "not-a-digest"))  # type: ignore[index,union-attr]
        self.assert_rejected(lambda value: value["candidate_artifacts"]["artifacts"][0].__setitem__("size_in_bytes", 0))  # type: ignore[index,union-attr]


if __name__ == "__main__":
    unittest.main()
