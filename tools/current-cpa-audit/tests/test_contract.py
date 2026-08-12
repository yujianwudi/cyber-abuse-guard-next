from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(HERE))

import acquire
import audit_contract
from audit_contract import (
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CPA_COMMIT,
    CPA_GO_MOD_SUM,
    CPA_MODULE_SUM,
    CPA_OFFICIAL_BINARY_SHA256,
    CPA_OFFICIAL_ASSET_NAME,
    CPA_OFFICIAL_ASSET_SHA256,
    CPA_OFFICIAL_ASSET_SIZE,
    CPA_TAG,
    MOCK_CONTRACT,
    RUN_CONFIG_SCHEMA,
    BoundCorpus,
    ContractError,
    build_execution_plan,
    load_json_file,
    require_timestamp,
    validate_corpus_manifest,
    validate_machine_evidence,
    validate_result,
    validate_run_config,
    validate_supplemental_result,
)
from fixtures import approved_policy, candidate_provenance, evidence_files, manifest


class ContractTests(unittest.TestCase):
    def test_timestamps_require_real_utc_z_values(self) -> None:
        for value in (
            "2026-08-09T01:02:03Z",
            "2026-08-09T01:02:03.123456Z",
        ):
            self.assertEqual(require_timestamp(value, "timestamp"), value)
        for value in (
            "garbage-timestamp-value",
            "2026-08-09T01:02:03+00:00",
            "2026-08-09T01:02:03.1234567Z",
            "2026-13-40T25:61:61Z",
        ):
            with self.subTest(value=value), self.assertRaises(ContractError):
                require_timestamp(value, "timestamp")

    def test_active_cpa_identity_is_exact(self) -> None:
        self.assertEqual(
            {
                "commit": CPA_COMMIT,
                "go_mod_sum": CPA_GO_MOD_SUM,
                "module_sum": CPA_MODULE_SUM,
                "official_binary_sha256": CPA_OFFICIAL_BINARY_SHA256,
                "official_asset_name": CPA_OFFICIAL_ASSET_NAME,
                "official_asset_sha256": CPA_OFFICIAL_ASSET_SHA256,
                "official_asset_size": CPA_OFFICIAL_ASSET_SIZE,
                "tag": CPA_TAG,
            },
            {
                "commit": "2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e",
                "go_mod_sum": "h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=",
                "module_sum": "h1:jz3yxTI7mp+ej2kI1T4OPs+QhIgP6Mmu5BGvipjQWRg=",
                "official_binary_sha256": "656cde7bfd966dbcaaa9d9260dd1de75716c0b9dead66d91ceb2d8d55f6d623a",
                "official_asset_name": "CLIProxyAPI_7.2.125_linux_amd64.tar.gz",
                "official_asset_sha256": (
                    "4e940b7dc5bdf867b5c58ca30f1b368fae6dc2e041e8a351d5c2c07f3f610233"
                ),
                "official_asset_size": 20_853_030,
                "tag": "v7.2.125",
            },
        )

    @staticmethod
    def closed_bound_corpus(root: Path) -> BoundCorpus:
        bound = object.__new__(BoundCorpus)
        bound.root = root
        bound.label = "closed test corpus"
        bound._operation_lock = threading.RLock()
        bound.root_fd = None
        bound.corpus_fd = None
        bound.uses_dir_fd = True
        root_info = root.stat()
        bound.root_identity = (root_info.st_dev, root_info.st_ino)
        bound.corpus_identity = (0, 0)
        return bound

    def test_bound_corpus_closed_descriptor_state_fails_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bound = self.closed_bound_corpus(Path(directory))
            operations = {
                "open": lambda: bound.write("corpus/sample.txt", b"sample"),
                "read": lambda: bound.read("corpus/sample.txt", "sample", 6),
                "unlink": lambda: bound.unlink_source("corpus/sample.txt", 6, "0" * 64),
            }
            for name, operation in operations.items():
                with self.subTest(name=name), self.assertRaisesRegex(
                    ContractError, "bound corpus descriptor is unavailable"
                ):
                    operation()
            root_operations = {
                "identity": bound.identity_problems,
                "finish_cleanup": bound.finish_cleanup,
            }
            for name, operation in root_operations.items():
                with self.subTest(name=name), self.assertRaisesRegex(
                    ContractError, "bound root descriptor is unavailable"
                ):
                    operation()

    def test_bound_corpus_descriptor_guards_survive_optimized_python(self) -> None:
        script = """
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from audit_contract import BoundCorpus, ContractError
import threading

bound = object.__new__(BoundCorpus)
bound.root = Path.cwd()
bound.label = "optimized test corpus"
bound._operation_lock = threading.RLock()
bound.root_fd = None
bound.corpus_fd = None
bound.uses_dir_fd = True
root_info = bound.root.stat()
bound.root_identity = (root_info.st_dev, root_info.st_ino)
bound.corpus_identity = (0, 0)
operations = (
    lambda: bound.write("corpus/sample.txt", b"sample"),
    lambda: bound.read("corpus/sample.txt", "sample", 6),
    lambda: bound.unlink_source("corpus/sample.txt", 6, "0" * 64),
)
for operation in operations:
    try:
        operation()
    except ContractError:
        continue
    raise SystemExit("closed descriptor operation did not fail explicitly")
for operation in (bound.identity_problems, bound.finish_cleanup):
    try:
        operation()
    except ContractError:
        continue
    raise SystemExit("closed root descriptor operation did not fail explicitly")
"""
        completed = subprocess.run(
            [sys.executable, "-O", "-c", script, str(TOOL)],
            cwd=TOOL,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout={completed.stdout!r} stderr={completed.stderr!r}",
        )

    @unittest.skipUnless(audit_contract.os.name == "posix", "dir-fd corpus contract")
    def test_bound_corpus_serializes_unlink_and_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus"
            corpus.mkdir()
            root_info = root.stat()
            corpus_info = corpus.stat()
            bound = BoundCorpus(
                root,
                {
                    "acquisition_root": {
                        "device": root_info.st_dev,
                        "inode": root_info.st_ino,
                    },
                    "corpus_directory": {
                        "device": corpus_info.st_dev,
                        "inode": corpus_info.st_ino,
                    },
                },
                "serialized test corpus",
            )
            raw = b"private corpus text"
            bound.write("corpus/sample.txt", raw)
            entered = threading.Event()
            release = threading.Event()
            close_finished = threading.Event()
            result: list[tuple[bool, list[str]]] = []
            original_unlink = audit_contract.os.unlink

            def blocking_unlink(*args: object, **kwargs: object) -> None:
                entered.set()
                if not release.wait(timeout=5):
                    raise RuntimeError("timed out waiting to release unlink")
                original_unlink(*args, **kwargs)

            def unlink_worker() -> None:
                result.append(
                    bound.unlink_source(
                        "corpus/sample.txt",
                        len(raw),
                        audit_contract.sha256_bytes(raw),
                    )
                )

            def close_worker() -> None:
                bound.close()
                close_finished.set()

            try:
                with mock.patch("audit_contract.os.unlink", side_effect=blocking_unlink):
                    unlink_thread = threading.Thread(target=unlink_worker)
                    unlink_thread.start()
                    self.assertTrue(entered.wait(timeout=5))
                    close_thread = threading.Thread(target=close_worker)
                    close_thread.start()
                    self.assertFalse(close_finished.wait(timeout=0.1))
                    release.set()
                    unlink_thread.join(timeout=5)
                    close_thread.join(timeout=5)
                self.assertFalse(unlink_thread.is_alive())
                self.assertFalse(close_thread.is_alive())
                self.assertTrue(close_finished.is_set())
                self.assertEqual(result, [(True, [])])
            finally:
                release.set()
                bound.close()

    def test_repository_policy_is_exact_and_closed(self) -> None:
        policy = load_json_file(TOOL / "repository-policy.json", "policy")
        validated = acquire.validate_policy(policy, require_approved=True)
        self.assertEqual(len(validated["repositories"]), 5)
        self.assertEqual(
            validated["reviewer"],
            {
                "identity": "Codex Round 13 exact-source review",
                "reviewed_at": "2026-08-12T02:04:47.780Z",
                "status": "approved",
            },
        )
        self.assertTrue(
            all(
                all(isinstance(value, str) and value for value in source["reviewed_source"].values())
                for repository in validated["repositories"]
                for source in repository["paths"]
            )
        )
        acquire.validate_policy(approved_policy(), require_approved=True)
        self.assertEqual(
            next(item for item in validated["repositories"] if item["key"] == "nerv")["retention"],
            "hash_identity_count_only",
        )

    def test_manifest_and_fixed_seed_plan_are_deterministic(self) -> None:
        value = validate_corpus_manifest(manifest())
        first = build_execution_plan(value, 1205, 3)
        second = build_execution_plan(value, 1205, 3)
        different = build_execution_plan(value, 1206, 3)
        self.assertEqual(first, second)
        self.assertNotEqual(first, different)
        self.assertEqual(len(first), 19 * 3 * 2 * 2 * 3)

    def test_manifest_missing_ground_truth_fails_closed(self) -> None:
        value = manifest()
        del value["semantic_cases"][0]["authorization"]
        with self.assertRaises(ContractError):
            validate_corpus_manifest(value)

    def test_manifest_missing_post_head_fails_closed(self) -> None:
        value = manifest()
        del value["head_observations"][0]["post"]
        with self.assertRaises(ContractError):
            validate_corpus_manifest(value)

    def test_manifest_extra_field_fails_closed(self) -> None:
        value = manifest()
        value["unreviewed"] = True
        with self.assertRaises(ContractError):
            validate_corpus_manifest(value)

    def test_run_config_is_closed_and_binds_cpa(self) -> None:
        config = {
            "corpus_manifest_sha256": "1" * 64,
            "identities": {
                "candidate": candidate_provenance(
                    commit="1" * 40,
                    tree="3" * 40,
                    so_sha256="2" * 64,
                ),
                "cag": {
                    "commit": "1" * 40,
                    "so_name": CAG_SO_NAME,
                    "so_sha256": "2" * 64,
                    "source_version": CAG_SOURCE_VERSION,
                    "tree": "3" * 40,
                },
                "cpa": {
                    "binary_path": "/usr/local/bin/CLIProxyAPI",
                    "binary_sha256": CPA_OFFICIAL_BINARY_SHA256,
                    "commit": CPA_COMMIT,
                    "image_id": "sha256:" + "4" * 64,
                    "image_ref": "registry.example/cpa@sha256:" + "5" * 64,
                    "official_asset_name": CPA_OFFICIAL_ASSET_NAME,
                    "official_asset_sha256": CPA_OFFICIAL_ASSET_SHA256,
                    "repo_digest": "registry.example/cpa@sha256:" + "5" * 64,
                    "tag": CPA_TAG,
                },
                "mock": {
                    "contract": MOCK_CONTRACT,
                    "image_id": "sha256:" + "7" * 64,
                    "image_ref": "registry.example/mock@sha256:" + "8" * 64,
                    "repo_digest": "registry.example/mock@sha256:" + "8" * 64,
                    "source_sha256": "9" * 64,
                },
            },
            "paths": {
                "candidate_manifest": "/srv/audit-candidate-manifest.json",
                "cag_repository": "/srv/cag",
                "cag_so": f"/srv/{CAG_SO_NAME}",
                "corpus_manifest": "/srv/acquisition/corpus-manifest.json",
                "cpa_official_asset": f"/srv/{CPA_OFFICIAL_ASSET_NAME}",
                "evidence_directory": "/srv/evidence",
                "mock_source": "/srv/counted_mock.py",
                "supplemental_zip": "/srv/Codex-full.zip",
                "supplemental_zip_manifest": "/srv/supplemental-zip-manifest.json",
                "supplemental_zip_policy": "/srv/supplemental-zip-policy.json",
            },
            "policy_sha256": "a" * 64,
            "run": {"cold_start_count": 3, "platform": "linux/amd64", "run_id": "unit-run", "seed": 1205},
            "schema": RUN_CONFIG_SCHEMA,
            "supplemental_zip": {
                "archive_bytes": 5830796,
                "archive_sha256": "23000a55f3922c9c2daf04e27d4bdf49d5f95109dd76ba25fa0b3f834c67ed1c",
                "manifest_sha256": "b" * 64,
                "policy_sha256": "9c6076e5fee920da9b59334c0cf9ddfa18f5c33a26a66719a04c609e77fb632a",
                "selected_entry_count": 4,
                "unique_reviewed_cases": 7,
            },
        }
        validate_run_config(config)
        extra = copy.deepcopy(config)
        extra["identities"]["cpa"]["untrusted"] = True
        with self.assertRaises(ContractError):
            validate_run_config(extra)
        wrong = copy.deepcopy(config)
        wrong["identities"]["cpa"]["tag"] = "v7.2.115"
        with self.assertRaises(ContractError):
            validate_run_config(wrong)
        wrong_asset = copy.deepcopy(config)
        wrong_asset["identities"]["cpa"]["official_asset_name"] = "cpa.tar.gz"
        with self.assertRaises(ContractError):
            validate_run_config(wrong_asset)
        wrong_asset_sha = copy.deepcopy(config)
        wrong_asset_sha["identities"]["cpa"]["official_asset_sha256"] = "6" * 64
        with self.assertRaises(ContractError):
            validate_run_config(wrong_asset_sha)
        wrong_cag_version = copy.deepcopy(config)
        wrong_cag_version["identities"]["cag"]["source_version"] = "0.16"
        with self.assertRaises(ContractError):
            validate_run_config(wrong_cag_version)
        for label, mutate in {
            "missing_candidate": lambda value: value["identities"].pop("candidate"),
            "artifact_digest": lambda value: value["identities"]["candidate"][
                "artifact"
            ].__setitem__("digest", "not-a-github-artifact-digest"),
            "artifact_id": lambda value: value["identities"]["candidate"][
                "artifact"
            ].__setitem__("id", "0"),
            "candidate_commit": lambda value: value["identities"]["candidate"][
                "source"
            ].__setitem__("commit", "f" * 40),
            "candidate_so": lambda value: value["identities"]["candidate"][
                "so"
            ].__setitem__("sha256", "f" * 64),
        }.items():
            wrong_candidate = copy.deepcopy(config)
            mutate(wrong_candidate)
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_run_config(wrong_candidate)

    def test_complete_machine_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, evidence, results = evidence_files(Path(directory))
            validated = validate_machine_evidence(source_manifest, evidence, results)
            self.assertEqual(validated["third_party_code_executions"], 0)
            self.assertEqual(validated["run"]["cold_start_count"], 3)

    def test_core_and_supplemental_result_planes_reject_cross_routing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_manifest, evidence, results = evidence_files(root)
            core_row = json.loads(results.read_bytes().splitlines()[0])
            supplemental_path = root / evidence["supplemental_zip_results"][
                "results_path"
            ]
            supplemental_row = json.loads(
                supplemental_path.read_bytes().splitlines()[0]
            )
            core_cases = {
                case["id"]: case for case in source_manifest["semantic_cases"]
            }
            supplemental_manifest = json.loads(
                (root / "supplemental-zip-manifest.json").read_bytes()
            )
            supplemental_cases = {
                case["id"]: case
                for case in supplemental_manifest["reviewed_cases"]
            }
            validate_result(core_row, core_cases, "core row")
            validate_supplemental_result(
                supplemental_row, supplemental_cases, "supplemental row"
            )
            with self.assertRaises(ContractError):
                validate_supplemental_result(
                    core_row, supplemental_cases, "misrouted core row"
                )
            with self.assertRaises(ContractError):
                validate_result(
                    supplemental_row, core_cases, "misrouted supplemental row"
                )

    def test_supplemental_authorized_ctf_binds_meta_override_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _source_manifest, evidence, _results = evidence_files(root)
            supplemental_manifest = json.loads(
                (root / "supplemental-zip-manifest.json").read_bytes()
            )
            cases = {
                case["id"]: case for case in supplemental_manifest["reviewed_cases"]
            }
            case_id = "supplemental-zip:ctf-sandbox:authorized-ctf"
            rows = [
                json.loads(line)
                for line in (
                    root / evidence["supplemental_zip_results"]["results_path"]
                ).read_text("utf-8").splitlines()
            ]
            selected = [
                item
                for item in rows
                if item["supplemental_case_id"] == case_id
                and item["cold_start"] == 1
            ]
            self.assertEqual(
                {
                    (item["mode"], item["protocol"], item["stream"])
                    for item in selected
                },
                {
                    (mode, protocol, stream)
                    for mode in ("audit", "balanced", "strict")
                    for protocol in ("chat", "responses")
                    for stream in (False, True)
                },
            )
            for row in selected:
                validate_supplemental_result(row, cases, "authorized CTF winner")
                for field, value in (
                    ("category", "credential_theft"),
                    ("winning_rule_id", "CRED-001"),
                ):
                    drifted = copy.deepcopy(row)
                    drifted["audit_event"][field] = value
                    with self.subTest(
                        mode=row["mode"],
                        protocol=row["protocol"],
                        stream=row["stream"],
                        field=field,
                    ), self.assertRaisesRegex(
                        ContractError, "reviewed supplemental winning rule"
                    ):
                        validate_supplemental_result(
                            drifted, cases, "drifted authorized CTF winner"
                        )

    def test_supplemental_machine_evidence_counts_hashes_and_cleanup_are_strict(self) -> None:
        mutations = {
            "missing_manifest": lambda value: value.pop("supplemental_zip_manifest"),
            "wrong_total": lambda value: value["supplemental_zip_summary"].__setitem__(
                "total_executions", 251
            ),
            "wrong_transport_error_count": lambda value: value[
                "supplemental_zip_summary"
            ].__setitem__("transport_error_executions", 1),
            "wrong_cold_count": lambda value: value["cold_starts"][0].__setitem__(
                "supplemental_execution_count", 83
            ),
            "wrong_cold_order": lambda value: value["cold_starts"][0].__setitem__(
                "supplemental_order_sha256", "f" * 64
            ),
            "created_member_file": lambda value: value["cleanup"].__setitem__(
                "supplemental_member_text_files_created", 1
            ),
            "archive_not_preserved": lambda value: value["cleanup"].__setitem__(
                "supplemental_input_archive_preserved", False
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source_manifest, evidence, results = evidence_files(root)
                mutate(evidence)
                with self.assertRaises(ContractError):
                    validate_machine_evidence(source_manifest, evidence, results)

    def test_missing_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, evidence, results = evidence_files(Path(directory))
            del evidence["identities"]["cpa"]["binary_sha256"]
            with self.assertRaises(ContractError):
                validate_machine_evidence(source_manifest, evidence, results)

    def test_candidate_provenance_is_required_closed_and_cag_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, baseline, results = evidence_files(Path(directory))
            mutations = {
                "missing": lambda value: value["identities"].pop("candidate"),
                "unknown": lambda value: value["identities"]["candidate"].__setitem__(
                    "untrusted", True
                ),
                "source_commit": lambda value: value["identities"]["candidate"][
                    "source"
                ].__setitem__("commit", "f" * 40),
                "so_sha": lambda value: value["identities"]["candidate"]["so"].__setitem__(
                    "sha256", "f" * 64
                ),
            }
            for label, mutate in mutations.items():
                evidence = copy.deepcopy(baseline)
                mutate(evidence)
                with self.subTest(label=label), self.assertRaises(ContractError):
                    validate_machine_evidence(source_manifest, evidence, results)

    def test_missing_quick_check_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, evidence, results = evidence_files(Path(directory))
            del evidence["cold_starts"][0]["sqlite"]["quick_check"]
            with self.assertRaises(ContractError):
                validate_machine_evidence(source_manifest, evidence, results)

    def test_machine_evidence_extra_field_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, evidence, results = evidence_files(Path(directory))
            evidence["trust_me"] = True
            with self.assertRaises(ContractError):
                validate_machine_evidence(source_manifest, evidence, results)

    def test_inconsistent_cold_result_digest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, evidence, results = evidence_files(Path(directory))
            evidence["cold_starts"][1]["results_sha256"] = "c" * 64
            with self.assertRaises(ContractError):
                validate_machine_evidence(source_manifest, evidence, results)

    def test_block_error_response_contract_is_mandatory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, _, results = evidence_files(Path(directory))
            cases = {case["id"]: case for case in source_manifest["semantic_cases"]}
            rows = [json.loads(line) for line in results.read_text("utf-8").splitlines()]
            blocked = next(row for row in rows if row["expected_action"] == "block_malicious_text")
            blocked["error_contract"]["schema_valid"] = False
            with self.assertRaises(ContractError):
                validate_result(blocked, cases, "mutated block")
            for field in ("auth", "mock", "provider", "usage"):
                drifted = copy.deepcopy(blocked)
                drifted["error_contract"]["schema_valid"] = True
                drifted["side_effect_deltas"][field] = 1
                with self.subTest(field=field), self.assertRaisesRegex(
                    ContractError, "zero-side-effect contract"
                ):
                    validate_result(drifted, cases, "mutated block side effect")

    def test_audit_malicious_event_preserves_disposition_kind_split(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, _, results = evidence_files(Path(directory))
            cases = {case["id"]: case for case in source_manifest["semantic_cases"]}
            rows = [json.loads(line) for line in results.read_text("utf-8").splitlines()]
            audited = next(
                row
                for row in rows
                if row["mode"] == "audit"
                and row["expected_action"] == "allow"
                and row["audit_event"] is not None
            )
            self.assertEqual(audited["audit_event"]["decision"], "audit_malicious_text")
            self.assertEqual(
                audited["audit_event"]["decision_kind"],
                "audit_eligible_malicious_text",
            )
            validate_result(audited, cases, "audited malicious allow")

            for field in ("category", "winning_rule_id"):
                unpaired = copy.deepcopy(audited)
                unpaired["audit_event"][field] = None
                with self.subTest(field=field), self.assertRaisesRegex(
                    ContractError, "winning category and rule"
                ):
                    validate_result(unpaired, cases, "unpaired audited winner")

            drifted = copy.deepcopy(audited)
            drifted["audit_event"]["decision"] = "audit_eligible_malicious_text"
            with self.assertRaisesRegex(ContractError, "paired Audit semantic event"):
                validate_result(drifted, cases, "drifted audited malicious allow")

    def test_result_extra_field_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, _, results = evidence_files(Path(directory))
            cases = {case["id"]: case for case in source_manifest["semantic_cases"]}
            row = json.loads(results.read_text("utf-8").splitlines()[0])
            row["request_text"] = "must never be retained"
            with self.assertRaises(ContractError):
                validate_result(row, cases, "extra field")


if __name__ == "__main__":
    unittest.main()
