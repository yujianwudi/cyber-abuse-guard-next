from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional local schema verifier
    Draft202012Validator = None  # type: ignore[assignment]


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

    def test_transport_tuple_arrays_declare_their_exact_minimum_lengths(self) -> None:
        schema = json.loads((TOOL / "machine-evidence.schema.json").read_text("utf-8"))
        properties = schema["$defs"]["transport"]["properties"]
        self.assertEqual(properties["modes"]["minItems"], 3)
        self.assertEqual(properties["protocols"]["minItems"], 2)
        self.assertEqual(properties["streams"]["minItems"], 2)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_transport_tuple_arrays_reject_truncated_prefixes(self) -> None:
        schema = json.loads((TOOL / "machine-evidence.schema.json").read_text("utf-8"))
        Draft202012Validator.check_schema(schema)
        transport_schema = {
            "$schema": schema["$schema"],
            "$defs": schema["$defs"],
            **schema["$defs"]["transport"],
        }
        validator = Draft202012Validator(transport_schema)
        transport = {
            "modes": ["audit", "balanced", "strict"],
            "protocols": ["chat", "responses"],
            "results_path": "transport-results.jsonl",
            "results_sha256": "a" * 64,
            "streams": [False, True],
            "transport_executions": 684,
        }
        self.assertTrue(validator.is_valid(transport))
        for field in ("modes", "protocols", "streams"):
            truncated = {**transport, field: transport[field][:-1]}
            with self.subTest(field=field):
                self.assertFalse(validator.is_valid(truncated))

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
