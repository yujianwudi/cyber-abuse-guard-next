from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))

from audit_contract import (
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CANDIDATE_ARTIFACT_NAME,
    CANDIDATE_REPOSITORY,
    CANDIDATE_WORKFLOW_NAME,
    CANDIDATE_WORKFLOW_PATH,
    CPA_COMMIT,
    CPA_OFFICIAL_BINARY_SHA256,
    CPA_OFFICIAL_ASSET_NAME,
    CPA_OFFICIAL_ASSET_SHA256,
    CPA_TAG,
)
from fixtures import evidence_files

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional local schema verifier
    Draft202012Validator = None  # type: ignore[assignment]


class SchemaTests(unittest.TestCase):
    def test_machine_schema_pins_the_active_cpa_identity(self) -> None:
        schema = json.loads((TOOL / "machine-evidence.schema.json").read_text("utf-8"))
        properties = schema["$defs"]["cpa_identity"]["properties"]
        self.assertEqual(
            properties["binary_sha256"], {"const": CPA_OFFICIAL_BINARY_SHA256}
        )
        self.assertEqual(properties["commit"], {"const": CPA_COMMIT})
        self.assertEqual(
            properties["official_asset_name"], {"const": CPA_OFFICIAL_ASSET_NAME}
        )
        self.assertEqual(
            properties["official_asset_sha256"],
            {"const": CPA_OFFICIAL_ASSET_SHA256},
        )
        self.assertEqual(properties["tag"], {"const": CPA_TAG})
        cag_properties = schema["$defs"]["cag_identity"]["properties"]
        self.assertEqual(cag_properties["so_name"], {"const": CAG_SO_NAME})
        self.assertEqual(
            cag_properties["source_version"], {"const": CAG_SOURCE_VERSION}
        )
        candidate = schema["$defs"]["candidate_identity"]["properties"]
        self.assertEqual(
            candidate["artifact"]["properties"]["name"],
            {"const": CANDIDATE_ARTIFACT_NAME},
        )
        self.assertEqual(candidate["repository"], {"const": CANDIDATE_REPOSITORY})
        self.assertEqual(
            candidate["workflow"]["properties"],
            {
                "name": {"const": CANDIDATE_WORKFLOW_NAME},
                "path": {"const": CANDIDATE_WORKFLOW_PATH},
            },
        )

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

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_machine_timestamps_require_strict_utc_z_syntax(self) -> None:
        schema = json.loads((TOOL / "machine-evidence.schema.json").read_text("utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        with tempfile.TemporaryDirectory() as directory:
            _, evidence, _ = evidence_files(Path(directory))
            self.assertTrue(validator.is_valid(evidence))
            for timestamp in (
                "garbage-timestamp-value",
                "2026-08-04T00:00:00+00:00",
                "2026-08-04T00:00:00.1234567Z",
                "2026-08-04 00:00:00Z",
                "2026-08-04T00:00:00Zjunk",
            ):
                wrong = copy.deepcopy(evidence)
                wrong["started_at"] = timestamp
                with self.subTest(timestamp=timestamp):
                    self.assertFalse(validator.is_valid(wrong))

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
