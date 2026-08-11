from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(HERE))

from audit_contract import SUPPLEMENTAL_ZIP_LIMITS  # noqa: E402
from fixtures import _fabricated_supplemental_entries  # noqa: E402


class FixtureTests(unittest.TestCase):
    def test_supplemental_offsets_handle_256_kib_incompressible_entry(self) -> None:
        policy = json.loads((TOOL / "supplemental-zip-policy.json").read_bytes())
        entries = copy.deepcopy(policy["entries"])
        entries[0]["compressed_bytes"] = SUPPLEMENTAL_ZIP_LIMITS[
            "max_selected_entry_bytes"
        ]
        entries[0]["uncompressed_bytes"] = entries[0]["compressed_bytes"]
        entries[0]["compression_method"] = 0

        approved = _fabricated_supplemental_entries(entries)

        self.assertEqual(approved[0]["data_offset"], 1000)
        self.assertEqual(
            approved[1]["local_header_offset"],
            approved[0]["data_offset"] + approved[0]["compressed_bytes"],
        )
        for previous, current in zip(approved, approved[1:]):
            self.assertLess(previous["local_header_offset"], previous["data_offset"])
            self.assertLessEqual(
                previous["data_offset"] + previous["compressed_bytes"],
                current["local_header_offset"],
            )


if __name__ == "__main__":
    unittest.main()
