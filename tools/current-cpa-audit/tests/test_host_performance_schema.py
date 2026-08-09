from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
SCHEMA_PATH = TOOL / "host-performance-evidence.schema.json"
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(HERE))

from audit_contract import (
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CPA_COMMIT,
    CPA_OFFICIAL_BINARY_SHA256,
    CPA_OFFICIAL_ASSET_NAME,
    CPA_OFFICIAL_ASSET_SHA256,
    CPA_TAG,
)

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional local schema verifier
    Draft202012Validator = None  # type: ignore[assignment]

from host_performance_fixtures import clone, evidence_bundle

METRICS = {
    "ordinary_plugin_overhead_p95_ms",
    "five_repository_activation_p95_ms",
    "public_adversarial_p95_ms",
    "public_adversarial_p99_ms",
    "fixed_workload_p99_regression_percent",
    "host_throughput_vs_cpa_only",
    "audit_queue_peak_ratio",
    "warm_rss_growth_60m_mib",
    "large_payload_full_copy_regression",
    "unexpected_http_or_infrastructure_errors",
    "restart_oom_panic",
}


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text("utf-8"))


class HostPerformanceSchemaTests(unittest.TestCase):
    def test_schema_pins_the_active_cpa_identity(self) -> None:
        definitions = load_schema()["$defs"]
        properties = definitions["cpa_identity"]["properties"]
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
        cag_properties = definitions["cag_identity"]["properties"]
        self.assertEqual(cag_properties["so_name"], {"const": CAG_SO_NAME})
        self.assertEqual(
            cag_properties["source_version"], {"const": CAG_SOURCE_VERSION}
        )
        candidate_properties = definitions["candidate_identity"]["properties"]
        self.assertEqual(
            candidate_properties["artifact"]["properties"]["name"],
            {"const": "cyber-abuse-guard-linux-amd64-audit-candidate"},
        )
        self.assertEqual(
            candidate_properties["source"]["properties"]["version"],
            {"const": CAG_SOURCE_VERSION},
        )
        self.assertEqual(
            candidate_properties["so"]["properties"]["name"],
            {"const": CAG_SO_NAME},
        )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_generated_evidence_validates_against_the_closed_schema(self) -> None:
        schema = load_schema()
        Draft202012Validator.check_schema(schema)
        evidence, *_ = evidence_bundle()
        Draft202012Validator(schema).validate(evidence)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_rejects_missing_or_extra_mount_projection_fields(self) -> None:
        validator = Draft202012Validator(load_schema())
        evidence, *_ = evidence_bundle()

        missing = clone(evidence)
        missing["mount_identity"].pop("cpa_only_mount_projection")
        self.assertFalse(validator.is_valid(missing))

        extra = clone(evidence)
        extra["mount_identity"]["cpa_cag_mount_projection"][
            "plaintext_source"
        ] = "/must-not-be-emitted"
        self.assertFalse(validator.is_valid(extra))

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_large_payload_evidence_is_required_and_cannot_claim_copy_count(self) -> None:
        validator = Draft202012Validator(load_schema())
        evidence, *_ = evidence_bundle()

        missing = clone(evidence)
        missing.pop("large_payload_resident_memory")
        self.assertFalse(validator.is_valid(missing))

        self_reported = clone(evidence)
        self_reported["metrics"]["large_payload_full_copy_regression"] = False
        self.assertFalse(validator.is_valid(self_reported))

        false_boundary = clone(evidence)
        false_boundary["large_payload_resident_memory"]["measurement_boundary"] = (
            "EXACT COPY COUNT"
        )
        self.assertFalse(validator.is_valid(false_boundary))

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_candidate_github_identifier_boundaries_match_runtime_contract(
        self,
    ) -> None:
        schema = load_schema()
        candidate_properties = schema["$defs"]["candidate_identity"]["properties"]
        self.assertEqual(candidate_properties["run_id"]["maxLength"], 32)
        self.assertEqual(candidate_properties["run_attempt"]["maxLength"], 20)

        validator = Draft202012Validator(schema)
        evidence, *_ = evidence_bundle()
        boundary = clone(evidence)
        boundary["identities"]["candidate"]["run_id"] = "9" * 32
        boundary["identities"]["candidate"]["run_attempt"] = "9" * 20
        self.assertEqual(list(validator.iter_errors(boundary)), [])

        for field, length in (("run_id", 33), ("run_attempt", 21)):
            oversized = clone(boundary)
            oversized["identities"]["candidate"][field] = "9" * length
            with self.subTest(field=field):
                self.assertFalse(validator.is_valid(oversized))

        for branch in ("main", "feature/release-1.2_candidate", "a" + "b" * 254):
            with self.subTest(kind="branch-accepted", branch=branch):
                accepted = clone(evidence)
                accepted["identities"]["candidate"]["head_branch"] = branch
                self.assertTrue(validator.is_valid(accepted))
        for branch in (
            "/leading",
            "trailing/",
            "trailing.",
            "double//slash",
            "double..dot",
            "topic@{1",
        ):
            with self.subTest(kind="branch-rejected", branch=branch):
                rejected = clone(evidence)
                rejected["identities"]["candidate"]["head_branch"] = branch
                self.assertFalse(validator.is_valid(rejected))

    def test_schema_is_2020_12_and_every_declared_object_is_closed(self) -> None:
        schema = load_schema()
        self.assertEqual(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )
        self.assertFalse(schema["additionalProperties"])

        open_objects: list[str] = []

        object_keywords = {
            "additionalProperties",
            "dependentRequired",
            "dependentSchemas",
            "maxProperties",
            "minProperties",
            "patternProperties",
            "properties",
            "propertyNames",
            "required",
            "unevaluatedProperties",
        }
        schema_maps = {
            "$defs",
            "dependentSchemas",
            "patternProperties",
            "properties",
        }
        schema_arrays = {"allOf", "anyOf", "oneOf", "prefixItems"}
        schema_values = {
            "additionalProperties",
            "contains",
            "contentSchema",
            "else",
            "if",
            "items",
            "not",
            "propertyNames",
            "then",
            "unevaluatedItems",
            "unevaluatedProperties",
        }

        def visit(value: Any, location: str) -> None:
            if not isinstance(value, dict):
                return
            declared_type = value.get("type")
            declares_object = (
                declared_type == "object"
                or (
                    isinstance(declared_type, list)
                    and "object" in declared_type
                )
                or any(key in value for key in object_keywords)
            )
            if declares_object and value.get("additionalProperties") is not False:
                open_objects.append(location)

            for key in schema_maps:
                children = value.get(key)
                if isinstance(children, dict):
                    for name, child in children.items():
                        visit(child, f"{location}/{key}/{name}")
            for key in schema_arrays:
                children = value.get(key)
                if isinstance(children, list):
                    for index, child in enumerate(children):
                        visit(child, f"{location}/{key}/{index}")
            for key in schema_values:
                child = value.get(key)
                if isinstance(child, dict):
                    visit(child, f"{location}/{key}")

        visit(schema, "$")
        self.assertEqual(open_objects, [])

    def test_timestamp_shape_and_matrix_workloads_match_runtime_contract(self) -> None:
        defs = load_schema()["$defs"]
        self.assertEqual(
            defs["timestamp"],
            {
                "type": "string",
                "format": "date-time",
                "pattern": (
                    "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:"
                    "[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"
                ),
                "minLength": 20,
                "maxLength": 64,
            },
        )
        self.assertEqual(
            defs["matrix_cell"]["properties"]["workload"]["enum"],
            [
                "fixed_workload",
                "ordinary",
                "five_repository_activation",
                "public",
            ],
        )
        self.assertIn(
            "total_elapsed_seconds", defs["matrix_cell"]["required"]
        )
        self.assertEqual(
            defs["matrix_cell"]["properties"]["total_elapsed_seconds"],
            {"type": "number", "exclusiveMinimum": 0},
        )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_rejects_nonemitted_timestamps_and_unknown_workloads(self) -> None:
        validator = Draft202012Validator(load_schema())
        evidence, *_ = evidence_bundle()

        for timestamp in (
            "2026-08-08T00:00:00Z",
            "2026-08-08T00:00:00.1Z",
            "2026-08-08T00:00:00.12Z",
            "2026-08-08T00:00:00.1234Z",
            "2026-08-08T00:00:00.12345Z",
            "2026-08-08T00:00:00.123456Z",
            "2026-08-08T00:00:00.123+00:00",
            "2026-08-08T00:00:00.123-05:00",
            "x" * 24,
        ):
            value = clone(evidence)
            value["started_at"] = timestamp
            with self.subTest(timestamp=timestamp):
                self.assertFalse(validator.is_valid(value))

        unknown_workload = clone(evidence)
        unknown_workload["matrix"][0]["workload"] = "invented_but_nonempty"
        self.assertFalse(validator.is_valid(unknown_workload))

    def test_plan_fixes_arms_concurrencies_and_warm_rss_duration(self) -> None:
        plan = load_schema()["$defs"]["plan"]
        self.assertEqual(
            plan["properties"]["arms"]["prefixItems"],
            [{"const": "cpa_only"}, {"const": "cpa_cag"}],
        )
        self.assertEqual(plan["properties"]["arms"]["minItems"], 2)
        self.assertEqual(plan["properties"]["arms"]["maxItems"], 2)
        self.assertFalse(plan["properties"]["arms"]["items"])
        self.assertEqual(
            plan["properties"]["concurrencies"]["prefixItems"],
            [{"const": 1}, {"const": 4}, {"const": 8}, {"const": 16}],
        )
        self.assertEqual(plan["properties"]["concurrencies"]["minItems"], 4)
        self.assertEqual(plan["properties"]["concurrencies"]["maxItems"], 4)
        self.assertFalse(plan["properties"]["concurrencies"]["items"])
        self.assertEqual(plan["properties"]["paired_repetitions"]["minimum"], 3)
        self.assertEqual(plan["properties"]["paired_repetitions"]["maximum"], 10)
        self.assertEqual(
            plan["properties"]["warm_rss_duration_seconds"], {"const": 3600}
        )
        self.assertEqual(plan["properties"]["warm_rss_concurrency"], {"const": 16})
        self.assertEqual(
            plan["properties"]["resource_sample_interval_ms"], {"const": 1000}
        )
        self.assertEqual(
            plan["properties"]["queue_sample_interval_ms"], {"const": 100}
        )
        self.assertEqual(
            plan["properties"]["warm_rss_sample_interval_seconds"], {"const": 1}
        )
        self.assertEqual(plan["properties"]["large_payload_bytes"], {"const": 4194304})
        self.assertEqual(
            plan["properties"]["large_payload_request_count"], {"const": 16}
        )
        self.assertEqual(
            plan["properties"]["large_payload_rss_sample_interval_ms"],
            {"const": 20},
        )

        warm_rss = load_schema()["$defs"]["warm_rss_60m"]["properties"]
        self.assertEqual(warm_rss["duration_seconds"], {"const": 3600})
        self.assertEqual(warm_rss["concurrency"], {"const": 16})

    def test_container_security_requires_exact_closed_roles_and_constraints(self) -> None:
        schema = load_schema()
        self.assertEqual(
            schema["properties"]["container_security"],
            {"$ref": "#/$defs/container_security"},
        )

        roles = {"cpa_only", "cpa_cag", "mock"}
        container_security = schema["$defs"]["container_security"]
        self.assertEqual(container_security["type"], "object")
        self.assertEqual(set(container_security["required"]), roles)
        self.assertEqual(set(container_security["properties"]), roles)
        self.assertFalse(container_security["additionalProperties"])

        for role in roles:
            with self.subTest(role=role):
                value_ref = container_security["properties"][role]["$ref"]
                value_schema = schema["$defs"][
                    value_ref.removeprefix("#/$defs/")
                ]
                self.assertEqual(value_schema["type"], "object")
                self.assertEqual(
                    set(value_schema["required"]),
                    {"no_new_privileges", "pids_limit"},
                )
                self.assertEqual(
                    set(value_schema["properties"]),
                    {"no_new_privileges", "pids_limit"},
                )
                self.assertFalse(value_schema["additionalProperties"])
                self.assertEqual(
                    value_schema["properties"]["no_new_privileges"],
                    {"const": True},
                )
                self.assertEqual(
                    value_schema["properties"]["pids_limit"],
                    {"type": "integer", "minimum": 1},
                )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_container_security_mutations_are_rejected(self) -> None:
        validator = Draft202012Validator(load_schema())
        evidence, *_ = evidence_bundle()

        false_no_new_privileges = clone(evidence)
        false_no_new_privileges["container_security"]["cpa_only"][
            "no_new_privileges"
        ] = False

        zero_pids_limit = clone(evidence)
        zero_pids_limit["container_security"]["cpa_cag"]["pids_limit"] = 0

        missing_role = clone(evidence)
        del missing_role["container_security"]["mock"]

        extra_role = clone(evidence)
        extra_role["container_security"]["unexpected"] = {
            "no_new_privileges": True,
            "pids_limit": 1,
        }

        for mutation, value in (
            ("false_no_new_privileges", false_no_new_privileges),
            ("zero_pids_limit", zero_pids_limit),
            ("missing_role", missing_role),
            ("extra_role", extra_role),
        ):
            with self.subTest(mutation=mutation):
                self.assertFalse(validator.is_valid(value))

    def test_metrics_and_gates_require_exactly_the_eleven_rt13_metrics(self) -> None:
        defs = load_schema()["$defs"]
        for name in ("metrics", "gates"):
            with self.subTest(name=name):
                section = defs[name]
                self.assertEqual(set(section["required"]), METRICS)
                self.assertEqual(set(section["properties"]), METRICS)
                self.assertFalse(section["additionalProperties"])

        for metric in METRICS:
            with self.subTest(gate=metric):
                ref = defs["gates"]["properties"][metric]["$ref"]
                gate = defs[ref.removeprefix("#/$defs/")]
                self.assertEqual(
                    set(gate["required"]), {"observed", "limit", "operator", "status"}
                )
                self.assertEqual(
                    set(gate["properties"]), {"observed", "limit", "operator", "status"}
                )

    def test_status_and_comparison_concurrency_are_fail_closed(self) -> None:
        schema = load_schema()
        self.assertEqual(
            schema["properties"]["status"]["enum"],
            ["PASS", "FAIL", "DIAGNOSTIC_NOT_BASELINE"],
        )
        comparisons = schema["properties"]["comparisons"]
        self.assertEqual(comparisons["minItems"], 4)
        self.assertEqual(comparisons["maxItems"], 4)
        self.assertFalse(comparisons["items"])
        comparison_defs = [
            item["$ref"].removeprefix("#/$defs/")
            for item in comparisons["prefixItems"]
        ]
        self.assertEqual(
            [
                schema["$defs"][name]["properties"]["concurrency"]["const"]
                for name in comparison_defs
            ],
            [1, 4, 8, 16],
        )


if __name__ == "__main__":
    unittest.main()
