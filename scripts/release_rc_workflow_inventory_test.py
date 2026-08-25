#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from release_rc_workflow_inventory import (
    InventoryError,
    MAX_INPUT_BYTES,
    PLATFORM_WORKFLOW_ALLOWLIST,
    REPOSITORY_WORKFLOWS,
    load_inventory,
    validate_inventory,
)


def document(*paths: str) -> list[dict[str, object]]:
    return [{"workflows": [{"path": path, "state": "active"} for path in paths]}]


class WorkflowInventoryTest(unittest.TestCase):
    def test_accepts_no_platform_entries(self) -> None:
        self.assertEqual(validate_inventory(document(*sorted(REPOSITORY_WORKFLOWS))), ())

    def test_accepts_each_bounded_platform_subset(self) -> None:
        platform = sorted(PLATFORM_WORKFLOW_ALLOWLIST)
        for extra in ((platform[0],), (platform[1],), tuple(platform)):
            with self.subTest(extra=extra):
                self.assertEqual(
                    validate_inventory(document(*sorted(REPOSITORY_WORKFLOWS), *extra)),
                    tuple(sorted(extra)),
                )

    def test_rejects_missing_repository_workflow(self) -> None:
        with self.assertRaisesRegex(InventoryError, "required repository workflow set changed"):
            validate_inventory(document(*sorted(REPOSITORY_WORKFLOWS)[1:]))

    def test_rejects_unknown_repository_workflow(self) -> None:
        with self.assertRaisesRegex(InventoryError, "unknown active workflow paths"):
            validate_inventory(
                document(*sorted(REPOSITORY_WORKFLOWS), ".github/workflows/unreviewed.yml")
            )

    def test_rejects_unknown_dynamic_workflow(self) -> None:
        with self.assertRaisesRegex(InventoryError, "unknown active workflow paths"):
            validate_inventory(document(*sorted(REPOSITORY_WORKFLOWS), "dynamic/unknown/job"))

    def test_rejects_duplicate_active_path_across_pages(self) -> None:
        path = sorted(REPOSITORY_WORKFLOWS)[0]
        value = document(*sorted(REPOSITORY_WORKFLOWS))
        value.append({"workflows": [{"path": path, "state": "active"}]})
        with self.assertRaisesRegex(InventoryError, "duplicate active workflow path"):
            validate_inventory(value)

    def test_ignores_inactive_unknown_path(self) -> None:
        value = document(*sorted(REPOSITORY_WORKFLOWS))
        value[0]["workflows"].append({"path": "dynamic/unknown/job", "state": "disabled_manually"})  # type: ignore[union-attr]
        self.assertEqual(validate_inventory(value), ())

    def test_rejects_malformed_pages_and_entries(self) -> None:
        for value in (None, [], {}, [{}], [{"workflows": [None]}]):
            with self.subTest(value=value):
                with self.assertRaises(InventoryError):
                    validate_inventory(value)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires Linux O_NOFOLLOW")
    def test_loads_regular_file_and_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "inventory.json"
            inventory.write_text(
                json.dumps(document(*sorted(REPOSITORY_WORKFLOWS))), encoding="utf-8"
            )
            self.assertEqual(validate_inventory(load_inventory(inventory)), ())
            link = root / "inventory-link.json"
            link.symlink_to(inventory.name)
            with self.assertRaisesRegex(InventoryError, "cannot open workflow inventory safely"):
                load_inventory(link)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires Linux O_NOFOLLOW")
    def test_load_rejects_oversize_and_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (MAX_INPUT_BYTES + 1))
            with self.assertRaisesRegex(InventoryError, "bounded regular file"):
                load_inventory(oversized)
            duplicate = root / "duplicate.json"
            duplicate.write_text('[{"workflows":[],"workflows":[]}]', encoding="utf-8")
            with self.assertRaisesRegex(InventoryError, "duplicate JSON key"):
                load_inventory(duplicate)


if __name__ == "__main__":
    unittest.main()
