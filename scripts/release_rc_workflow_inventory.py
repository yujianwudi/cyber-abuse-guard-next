#!/usr/bin/env python3
"""Validate the bounded repository and GitHub platform workflow inventory."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Iterable

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_PAGES = 100
MAX_WORKFLOWS = 512
MAX_PATH_BYTES = 512

REPOSITORY_WORKFLOWS = frozenset(
    {
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/policy-gate.yml",
        ".github/workflows/release-rc.yml",
    }
)
PLATFORM_WORKFLOW_ALLOWLIST = frozenset(
    {
        "dynamic/dependabot/dependabot-updates",
        "dynamic/dependabot/update-graph",
    }
)


class InventoryError(ValueError):
    """The API workflow inventory does not match the reviewed contract."""


def reject_duplicate_keys(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def validate_inventory(document: Any) -> tuple[str, ...]:
    if not isinstance(document, list) or not document or len(document) > MAX_PAGES:
        raise InventoryError("workflow inventory must be a bounded non-empty page array")

    active: set[str] = set()
    workflow_count = 0
    for page in document:
        if not isinstance(page, dict) or not isinstance(page.get("workflows"), list):
            raise InventoryError("each workflow inventory page must contain a workflows array")
        for workflow in page["workflows"]:
            workflow_count += 1
            if workflow_count > MAX_WORKFLOWS:
                raise InventoryError("workflow inventory exceeds the reviewed item bound")
            if not isinstance(workflow, dict):
                raise InventoryError("workflow inventory entries must be objects")
            path = workflow.get("path")
            state = workflow.get("state")
            if not isinstance(path, str) or not path or len(path.encode("utf-8")) > MAX_PATH_BYTES:
                raise InventoryError("workflow path must be a bounded non-empty string")
            if not isinstance(state, str) or not state:
                raise InventoryError("workflow state must be a non-empty string")
            if state != "active":
                continue
            if path in active:
                raise InventoryError(f"duplicate active workflow path: {path}")
            active.add(path)

    repository_active = active & REPOSITORY_WORKFLOWS
    if repository_active != REPOSITORY_WORKFLOWS:
        missing = sorted(REPOSITORY_WORKFLOWS - repository_active)
        raise InventoryError(f"required repository workflow set changed; missing={missing}")

    unknown = active - REPOSITORY_WORKFLOWS - PLATFORM_WORKFLOW_ALLOWLIST
    if unknown:
        raise InventoryError(f"unknown active workflow paths: {sorted(unknown)}")

    return tuple(sorted(active & PLATFORM_WORKFLOW_ALLOWLIST))


def load_inventory(path: Path) -> Any:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise InventoryError("workflow inventory validation requires O_NOFOLLOW")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | nofollow)
    except OSError as exc:
        raise InventoryError(f"cannot open workflow inventory safely: {exc}") from exc
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size <= 0
                or opened.st_size > MAX_INPUT_BYTES
            ):
                raise InventoryError("workflow inventory must be a bounded regular file")
            raw = handle.read(MAX_INPUT_BYTES + 1)
            if not raw or len(raw) > MAX_INPUT_BYTES:
                raise InventoryError("workflow inventory read exceeds the reviewed byte bound")
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"cannot parse workflow inventory: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()
    try:
        platform = validate_inventory(load_inventory(args.input))
    except InventoryError as exc:
        print(f"release workflow inventory rejected: {exc}", file=sys.stderr)
        return 1
    print(
        "release workflow inventory passed: "
        f"repository={len(REPOSITORY_WORKFLOWS)} platform={len(platform)}"
    )
    return os.EX_OK


if __name__ == "__main__":
    raise SystemExit(main())
