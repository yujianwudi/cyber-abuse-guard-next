from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))


class SchemaTests(unittest.TestCase):
    def test_machine_schema_is_valid_json_and_every_object_is_closed(self) -> None:
        schema = json.loads((TOOL / "machine-evidence.schema.json").read_text("utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schema["$defs"]["corpus"]["properties"]["unique_semantic_cases"],
            {"const": 19},
        )
        self.assertIn(
            "user", schema["$defs"]["container"]["required"]
        )
        self.assertEqual(schema["$defs"]["run"]["properties"]["cold_start_count"]["maximum"], 10)

        open_objects: list[str] = []

        def visit(value: Any, location: str) -> None:
            if isinstance(value, dict):
                declares_object = value.get("type") == "object" or "properties" in value
                if declares_object and value.get("additionalProperties") is not False:
                    open_objects.append(location)
                for key, child in value.items():
                    visit(child, f"{location}/{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, f"{location}/{index}")

        visit(schema, "$")
        self.assertEqual(open_objects, [])

    def test_schema_documents_required_fail_closed_gates(self) -> None:
        raw = (TOOL / "machine-evidence.schema.json").read_text("utf-8")
        for token in (
            '"quick_check"',
            '"third_party_code_executions"',
            '"binary_sha256"',
            '"repo_digest"',
            '"runtime_config_sha256"',
            '"all_owned_resources_absent"',
            '"business_snapshots"',
        ):
            with self.subTest(token=token):
                self.assertIn(token, raw)


if __name__ == "__main__":
    unittest.main()
