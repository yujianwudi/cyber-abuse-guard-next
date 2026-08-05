from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from typing import Any, Mapping
from unittest import mock
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(HERE))

import acquire
import run
import validate as validator_cli
from audit_contract import (
    BLOCK_REFUSAL_MESSAGE,
    CPA_COMMIT,
    CPA_TAG,
    MOCK_CONTRACT,
    RUN_CONFIG_SCHEMA,
    ContractError,
    canonical_bytes,
    load_json_file,
    review_sha256,
    sha256_bytes,
    validate_corpus_manifest,
    validate_block_response,
    build_execution_plan,
    validate_evidence_run_config,
    validate_manifest_policy,
    validate_machine_evidence,
    validate_result,
    validate_run_config,
)
from fixtures import STAMP, digest, evidence_files, manifest


def valid_run_config() -> dict[str, Any]:
    return {
        "corpus_manifest_sha256": "1" * 64,
        "identities": {
            "cag": {"commit": "1" * 40, "so_sha256": "2" * 64, "tree": "3" * 40},
            "cpa": {
                "binary_path": "/usr/local/bin/CLIProxyAPI",
                "binary_sha256": "3" * 64,
                "commit": CPA_COMMIT,
                "image_id": "sha256:" + "4" * 64,
                "image_ref": "registry.example/cpa@sha256:" + "5" * 64,
                "official_asset_name": "cpa.tar.gz",
                "official_asset_sha256": "6" * 64,
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
            "cag_repository": "/srv/cag",
            "cag_so": "/srv/cag.so",
            "corpus_manifest": "/srv/acquisition/corpus-manifest.json",
            "cpa_official_asset": "/srv/cpa.tar.gz",
            "evidence_directory": "/srv/evidence",
            "mock_source": "/srv/counted_mock.py",
        },
        "policy_sha256": "a" * 64,
        "run": {
            "cold_start_count": 3,
            "platform": "linux/amd64",
            "run_id": "unit-run",
            "seed": 1205,
        },
        "schema": RUN_CONFIG_SCHEMA,
    }


def rewrite_results(
    evidence: dict[str, Any], results_path: Path, rows: list[dict[str, Any]]
) -> None:
    raw = b"".join(canonical_bytes(row) + b"\n" for row in rows)
    results_path.write_bytes(raw)
    evidence["transport"]["results_sha256"] = sha256_bytes(raw)
    for cold in evidence["cold_starts"]:
        cold_raw = b"".join(
            canonical_bytes(row) + b"\n"
            for row in rows
            if row["cold_start"] == cold["index"]
        )
        cold["results_sha256"] = sha256_bytes(cold_raw)


def config_bound_to_evidence(
    evidence: dict[str, Any], evidence_directory: str = "/srv/evidence"
) -> tuple[dict[str, Any], bytes]:
    cpa = copy.deepcopy(evidence["identities"]["cpa"])
    cpa["image_ref"] = cpa["repo_digest"]
    mock_identity = evidence["identities"]["mock"]
    mock_config = {**copy.deepcopy(mock_identity), "image_ref": mock_identity["repo_digest"]}
    config = {
        "corpus_manifest_sha256": evidence["corpus"]["manifest_sha256"],
        "identities": {
            "cag": copy.deepcopy(evidence["identities"]["cag"]),
            "cpa": cpa,
            "mock": mock_config,
        },
        "paths": {
            "cag_repository": "/srv/cag",
            "cag_so": "/srv/cag.so",
            "corpus_manifest": "/srv/acquisition/corpus-manifest.json",
            "cpa_official_asset": "/srv/cpa.tar.gz",
            "evidence_directory": evidence_directory,
            "mock_source": "/srv/counted_mock.py",
        },
        "policy_sha256": evidence["identities"]["runner"]["policy_sha256"],
        "run": copy.deepcopy(evidence["run"]),
        "schema": RUN_CONFIG_SCHEMA,
    }
    raw = canonical_bytes(config) + b"\n"
    evidence["identities"]["configuration"]["input_sha256"] = sha256_bytes(raw)
    return config, raw


class FakeGitHubClient:
    """Deterministic GitHub facade; it has no socket or subprocess surface."""

    def __init__(self, policy: Mapping[str, Any], corrupt_url: str | None = None) -> None:
        self.corrupt_url = corrupt_url
        self.calls: list[tuple[str, str]] = []
        self.json_values: dict[str, Any] = {}
        self.fetch_values: dict[str, bytes] = {}
        self.reviewed_sources: dict[tuple[str, str], dict[str, str]] = {}
        for index, repository in enumerate(policy["repositories"], start=1):
            slug = repository["repository"]
            encoded_slug = "/".join(quote(part, safe="") for part in slug.split("/"))
            commit = f"{index:x}" * 40
            tree = f"{index + 5:x}" * 40
            metadata_url = f"https://api.github.com/repos/{encoded_slug}"
            head_url = f"{metadata_url}/commits/main"
            tree_url = f"{metadata_url}/git/trees/{tree}?recursive=1"
            entries: list[dict[str, Any]] = []
            for selected in repository["paths"]:
                path = selected["path"]
                if selected["kind"] == "markdown_zip":
                    text = f"reviewed inert archive text for {slug}:{path}\n".encode(
                        "utf-8"
                    )
                    buffer = io.BytesIO()
                    with zipfile.ZipFile(
                        buffer, "w", compression=zipfile.ZIP_DEFLATED
                    ) as archive:
                        member = zipfile.ZipInfo(
                            selected["archive_member"],
                            date_time=(2026, 8, 4, 0, 0, 0),
                        )
                        member.compress_type = zipfile.ZIP_DEFLATED
                        member.create_system = 3
                        member.external_attr = 0o600 << 16
                        archive.writestr(member, text)
                    raw = buffer.getvalue()
                else:
                    text = f"reviewed inert text for {slug}:{path}\n".encode("utf-8")
                    raw = text
                raw_url = (
                    f"https://raw.githubusercontent.com/{encoded_slug}/{commit}/"
                    f"{quote(path, safe='/')}"
                )
                self.fetch_values[raw_url] = raw
                self.reviewed_sources[(repository["key"], path)] = {
                    "blob_sha1": acquire.git_blob_sha1(raw),
                    "commit": commit,
                    "source_sha256": sha256_bytes(raw),
                    "text_sha256": sha256_bytes(text),
                    "tree": tree,
                }
                entries.append(
                    {
                        "mode": "100644",
                        "path": path,
                        "sha": acquire.git_blob_sha1(raw),
                        "size": len(raw),
                        "type": "blob",
                    }
                )
            self.json_values[metadata_url] = {
                "default_branch": "main",
                "full_name": slug,
            }
            self.json_values[head_url] = {
                "commit": {"tree": {"sha": tree}},
                "sha": commit,
            }
            self.json_values[tree_url] = {
                "sha": tree,
                "tree": entries,
                "truncated": False,
            }

    @staticmethod
    def receipt(url: str, raw: bytes | None = None) -> acquire.FetchReceipt:
        return acquire.FetchReceipt(
            observed_at=STAMP,
            url=url,
            body_sha256=sha256_bytes(raw if raw is not None else url.encode("utf-8")),
            etag=f'"{digest(url)[:16]}"',
        )

    def json(self, url: str, maximum: int = acquire.MAX_API_BYTES) -> tuple[Any, acquire.FetchReceipt]:
        del maximum
        self.calls.append(("json", url))
        if url not in self.json_values:
            raise AssertionError(f"unexpected JSON URL: {url}")
        return copy.deepcopy(self.json_values[url]), self.receipt(url)

    def fetch(self, url: str, maximum: int) -> tuple[bytes, acquire.FetchReceipt]:
        self.calls.append(("fetch", url))
        if url not in self.fetch_values:
            raise AssertionError(f"unexpected raw URL: {url}")
        raw = self.fetch_values[url]
        if url == self.corrupt_url:
            raw += b"corrupt"
        if len(raw) > maximum:
            raise AssertionError("fixture escaped the acquisition byte bound")
        return raw, self.receipt(url, raw)


def approve_policy_for_client(
    pending_policy: Mapping[str, Any], client: FakeGitHubClient
) -> dict[str, Any]:
    policy = copy.deepcopy(pending_policy)
    policy["reviewer"] = {
        "identity": "unit-test-current-source-reviewer",
        "reviewed_at": STAMP,
        "status": "approved",
    }
    for repository in policy["repositories"]:
        for source in repository["paths"]:
            source["reviewed_source"] = copy.deepcopy(
                client.reviewed_sources[(repository["key"], source["path"])]
            )
    return acquire.validate_policy(policy, require_approved=True)


def pending_policy_from_checked_in(policy: Mapping[str, Any]) -> dict[str, Any]:
    pending = copy.deepcopy(policy)
    pending["reviewer"] = {"identity": None, "reviewed_at": None, "status": "pending"}
    for repository in pending["repositories"]:
        for source in repository["paths"]:
            source["reviewed_source"] = {
                "blob_sha1": None,
                "commit": None,
                "source_sha256": None,
                "text_sha256": None,
                "tree": None,
            }
    return acquire.validate_policy(pending)


class AcquisitionIntegrationTests(unittest.TestCase):
    def test_fake_acquisition_stays_on_exact_allowlist_and_executes_nothing(self) -> None:
        policy_path = TOOL / "repository-policy.json"
        policy = pending_policy_from_checked_in(
            acquire.validate_policy(load_json_file(policy_path, "policy"), require_approved=True)
        )
        policy_raw = canonical_bytes(policy) + b"\n"
        client = FakeGitHubClient(policy)
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "acquisition"
            result = acquire.Acquirer(
                policy, client, output, sha256_bytes(policy_raw)
            ).acquire()
            self.assertEqual(result["repository_count"], 5)
            self.assertEqual(result["source_count"], 11)
            self.assertEqual(result["third_party_code_executions"], 0)
            self.assertEqual(result["artifact_status"], "candidate")
            self.assertEqual(result["policy_review_status"], "pending")
            self.assertTrue(
                all(
                    case["reviewer"]
                    == {
                        "identity": None,
                        "review_sha256": None,
                        "reviewed_at": None,
                        "status": "pending",
                    }
                    for case in result["semantic_cases"]
                )
            )
            raw_calls = {url for kind, url in client.calls if kind == "fetch"}
            self.assertEqual(raw_calls, set(client.fetch_values))
            for _, url in client.calls:
                acquire.validate_github_url(url)
            validate_manifest_policy(result, policy)
            with self.assertRaises(ContractError):
                validate_manifest_policy(result, policy, require_approved=True)
            with self.assertRaises(ContractError):
                validator_cli.bind_policy(result)
            removed = acquire.discard_candidate_texts(
                output / "corpus-manifest.json"
            )
            self.assertEqual(removed, result["source_count"])
            self.assertFalse((output / "corpus").exists())

    def test_approved_pins_bind_every_current_source_and_ground_truth(self) -> None:
        pending_path = TOOL / "repository-policy.json"
        pending = pending_policy_from_checked_in(
            acquire.validate_policy(load_json_file(pending_path, "policy"), require_approved=True)
        )
        discovery_client = FakeGitHubClient(pending)
        policy = approve_policy_for_client(pending, discovery_client)
        client = FakeGitHubClient(policy)
        policy_raw = canonical_bytes(policy) + b"\n"
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "approved-acquisition"
            result = acquire.Acquirer(
                policy, client, output, sha256_bytes(policy_raw)
            ).acquire()
            self.assertEqual(result["policy_review_status"], "approved")
            validate_manifest_policy(result, policy, require_approved=True)
            ordinary_tamper = copy.deepcopy(result)
            ordinary_case = next(
                case
                for case in ordinary_tamper["semantic_cases"]
                if case["source"]["archive_member"] is None
            )
            ordinary_case["source"]["source_sha256"] = digest(
                "non-archive-raw-text-drift"
            )
            with self.assertRaisesRegex(
                ContractError, "source text input must preserve the raw source SHA-256"
            ):
                validate_corpus_manifest(ordinary_tamper)
            tampered = copy.deepcopy(result)
            tampered_case = tampered["semantic_cases"][0]
            tampered_case["label_reason"] = "locally rewritten ground truth"
            tampered_case["reviewer"]["review_sha256"] = review_sha256(tampered_case)
            validate_corpus_manifest(tampered)
            with self.assertRaises(ContractError):
                validate_manifest_policy(tampered, policy, require_approved=True)

    def test_mid_acquisition_failure_removes_all_written_nerv_text(self) -> None:
        policy_path = TOOL / "repository-policy.json"
        policy = pending_policy_from_checked_in(
            acquire.validate_policy(load_json_file(policy_path, "policy"), require_approved=True)
        )
        client = FakeGitHubClient(policy)
        corrupt_url = next(
            url for url in client.fetch_values if url.endswith("/docs/README_CN.md")
        )
        client.corrupt_url = corrupt_url
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "acquisition"
            with self.assertRaises(ContractError):
                acquire.Acquirer(policy, client, output, digest("policy")).acquire()
            self.assertFalse(output.exists())
            self.assertFalse(any(Path(parent).rglob("*.txt")))

    @unittest.skipUnless(
        os.name == "posix" and os.open in os.supports_dir_fd,
        "requires the Linux dir-fd cleanup contract",
    )
    def test_mid_acquisition_directory_swap_cleans_the_bound_original(self) -> None:
        policy_path = TOOL / "repository-policy.json"
        policy = pending_policy_from_checked_in(
            acquire.validate_policy(load_json_file(policy_path, "policy"), require_approved=True)
        )
        client = FakeGitHubClient(policy)
        original_write = acquire.BoundCorpus.write
        swapped = False

        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            output = root / "acquisition"
            escaped = root / "escaped-original-corpus"

            def swap_after_first_nerv(
                bound: Any, relative: str, raw: bytes, mode: int = 0o600
            ) -> None:
                nonlocal swapped
                original_write(bound, relative, raw, mode)
                if not swapped and relative.startswith("corpus/nerv--"):
                    corpus = bound.root / "corpus"
                    corpus.rename(escaped)
                    corpus.mkdir(mode=0o700)
                    swapped = True
                    raise ContractError("synthetic directory swap after NERV write")

            with (
                mock.patch.object(
                    acquire.BoundCorpus, "write", new=swap_after_first_nerv
                ),
                self.assertRaises(ContractError),
            ):
                acquire.Acquirer(
                    policy,
                    client,
                    output,
                    digest("pending-policy"),
                ).acquire()

            self.assertTrue(swapped)
            self.assertFalse(any(root.rglob("*.txt")))

    def test_mixed_pending_or_wrong_approved_pins_fail_closed(self) -> None:
        policy_path = TOOL / "repository-policy.json"
        pending = pending_policy_from_checked_in(
            acquire.validate_policy(load_json_file(policy_path, "policy"), require_approved=True)
        )
        mixed = copy.deepcopy(pending)
        mixed["repositories"][0]["paths"][0]["reviewed_source"]["commit"] = (
            "1" * 40
        )
        with self.assertRaises(ContractError):
            acquire.validate_policy(mixed)

        discovery_client = FakeGitHubClient(pending)
        approved = approve_policy_for_client(pending, discovery_client)
        zero_pinned = copy.deepcopy(approved)
        zero_pinned["repositories"][0]["paths"][0]["reviewed_source"][
            "text_sha256"
        ] = "0" * 64
        with self.assertRaises(ContractError):
            acquire.validate_policy(zero_pinned, require_approved=True)
        approved["repositories"][0]["paths"][0]["reviewed_source"][
            "text_sha256"
        ] = digest("wrong-reviewed-text")
        acquire.validate_policy(approved, require_approved=True)
        client = FakeGitHubClient(approved)
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "wrong-pin-acquisition"
            with self.assertRaises(ContractError):
                acquire.Acquirer(
                    approved,
                    client,
                    output,
                    sha256_bytes(canonical_bytes(approved) + b"\n"),
                ).acquire()
            self.assertFalse(output.exists())

    def test_write_exclusive_rejects_a_hardlink_created_while_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "source.txt"
            leaked = root / "outside-link.txt"
            real_fsync = os.fsync

            def link_during_fsync(descriptor: int) -> None:
                real_fsync(descriptor)
                os.link(target, leaked)

            with (
                mock.patch.object(
                    acquire.os, "fsync", side_effect=link_during_fsync
                ),
                self.assertRaises(ContractError),
            ):
                acquire.write_exclusive(target, b"reviewed inert text\n")
            self.assertTrue(leaked.is_file())
            self.assertEqual(leaked.read_bytes(), b"reviewed inert text\n")

    def test_hardlinked_corpus_fails_validation_discard_and_run_cleanup(self) -> None:
        pending_path = TOOL / "repository-policy.json"
        pending = pending_policy_from_checked_in(
            acquire.validate_policy(load_json_file(pending_path, "policy"), require_approved=True)
        )
        discovery_client = FakeGitHubClient(pending)
        policy = approve_policy_for_client(pending, discovery_client)
        policy_raw = canonical_bytes(policy) + b"\n"

        def acquired(output: Path) -> dict[str, Any]:
            return acquire.Acquirer(
                policy,
                FakeGitHubClient(policy),
                output,
                sha256_bytes(policy_raw),
            ).acquire()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for operation in ("discard", "run_cleanup"):
                with self.subTest(operation=operation):
                    output = root / operation
                    source_manifest = acquired(output)
                    relative = next(
                        case["source"]["corpus_file"]
                        for case in source_manifest["semantic_cases"]
                        if case["source"]["repository_key"] == "nerv"
                    )
                    source = output / relative
                    leaked = root / f"{operation}-outside-nerv.txt"
                    original = source.read_bytes()
                    os.link(source, leaked)
                    self.assertEqual(source.stat().st_nlink, 2)

                    with self.assertRaises(ContractError):
                        validate_corpus_manifest(source_manifest, output)
                    if operation == "discard":
                        with self.assertRaisesRegex(ContractError, r"hard.?link"):
                            acquire.discard_candidate_texts(
                                output / "corpus-manifest.json"
                            )
                    else:
                        with self.assertRaises(run.CleanupFailure) as raised:
                            run.remove_manifest_corpus(source_manifest, output)
                        self.assertTrue(raised.exception.cleanup_error_id)

                    self.assertTrue(source.is_file())
                    self.assertTrue(leaked.is_file())
                    self.assertEqual(source.read_bytes(), original)
                    self.assertEqual(leaked.read_bytes(), original)

    def test_corpus_directory_swap_with_same_name_decoys_fails_cleanup(self) -> None:
        pending_path = TOOL / "repository-policy.json"
        pending = pending_policy_from_checked_in(
            acquire.validate_policy(load_json_file(pending_path, "policy"), require_approved=True)
        )
        discovery_client = FakeGitHubClient(pending)
        policy = approve_policy_for_client(pending, discovery_client)
        policy_raw = canonical_bytes(policy) + b"\n"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for operation in ("discard", "run_cleanup"):
                with self.subTest(operation=operation):
                    output = root / operation
                    source_manifest = acquire.Acquirer(
                        policy,
                        FakeGitHubClient(policy),
                        output,
                        sha256_bytes(policy_raw),
                    ).acquire()
                    validate_corpus_manifest(source_manifest, output)
                    corpus = output / "corpus"
                    escaped = root / f"{operation}-escaped-original-corpus"
                    corpus.rename(escaped)
                    corpus.mkdir()
                    expected = sorted(
                        {
                            case["source"]["corpus_file"]
                            for case in source_manifest["semantic_cases"]
                        }
                    )
                    for relative in expected:
                        (output / relative).write_bytes(b"same-name decoy\n")

                    if operation == "discard":
                        with self.assertRaises(ContractError):
                            acquire.discard_candidate_texts(
                                output / "corpus-manifest.json"
                            )
                    else:
                        with self.assertRaises(run.CleanupFailure):
                            run.remove_manifest_corpus(source_manifest, output)

                    escaped_files = sorted(escaped.iterdir())
                    self.assertEqual(len(escaped_files), source_manifest["source_count"])
                    self.assertGreater(sum(path.stat().st_size for path in escaped_files), 0)

    def test_missing_expected_source_fails_discard_and_run_cleanup(self) -> None:
        pending_path = TOOL / "repository-policy.json"
        pending = pending_policy_from_checked_in(
            acquire.validate_policy(load_json_file(pending_path, "policy"), require_approved=True)
        )
        discovery_client = FakeGitHubClient(pending)
        policy = approve_policy_for_client(pending, discovery_client)
        policy_raw = canonical_bytes(policy) + b"\n"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for operation in ("discard", "run_cleanup"):
                with self.subTest(operation=operation):
                    output = root / operation
                    source_manifest = acquire.Acquirer(
                        policy,
                        FakeGitHubClient(policy),
                        output,
                        sha256_bytes(policy_raw),
                    ).acquire()
                    relative = next(
                        case["source"]["corpus_file"]
                        for case in source_manifest["semantic_cases"]
                        if case["source"]["repository_key"] == "nerv"
                    )
                    source = output / relative
                    escaped = root / f"{operation}-escaped-nerv.txt"
                    original = source.read_bytes()
                    source.rename(escaped)

                    if operation == "discard":
                        with self.assertRaises(ContractError):
                            acquire.discard_candidate_texts(
                                output / "corpus-manifest.json"
                            )
                    else:
                        with self.assertRaises(run.CleanupFailure):
                            run.remove_manifest_corpus(source_manifest, output)

                    self.assertTrue(escaped.is_file())
                    self.assertEqual(escaped.read_bytes(), original)


class ClosedContractRegressionTests(unittest.TestCase):
    def test_manifest_requires_the_full_fixed_source_set(self) -> None:
        value = manifest()
        removed = [
            case
            for case in value["semantic_cases"]
            if case["source"]["path"] == "examples/gpt5.4-unrestricted.md"
        ]
        value["semantic_cases"] = [
            case for case in value["semantic_cases"] if case not in removed
        ]
        value["source_count"] -= 1
        value["unique_content_hashes"] -= 1
        value["unique_semantic_cases"] -= len(removed)
        with self.assertRaises(ContractError):
            validate_corpus_manifest(value)

    def test_moved_post_head_fails_closed(self) -> None:
        value = manifest()
        value["head_observations"][0]["post"]["commit"] = "e" * 40
        with self.assertRaises(ContractError):
            validate_corpus_manifest(value)

    def test_run_config_rejects_unsafe_paths_ids_and_zero_identities(self) -> None:
        validate_run_config(valid_run_config())
        mutations = {
            "docker_name_colon": lambda value: value["run"].__setitem__(
                "run_id", "unit:run"
            ),
            "docker_name_uppercase": lambda value: value["run"].__setitem__(
                "run_id", "Unit-run"
            ),
            "path_traversal": lambda value: value["paths"].__setitem__(
                "evidence_directory", "/srv/../escape"
            ),
            "mount_delimiter": lambda value: value["paths"].__setitem__(
                "cag_so", "/srv/cag,other.so"
            ),
            "excessive_cold_starts": lambda value: value["run"].__setitem__(
                "cold_start_count", 11
            ),
            "zero_image_id": lambda value: value["identities"]["cpa"].__setitem__(
                "image_id", "sha256:" + "0" * 64
            ),
            "zero_repo_digest": lambda value: value["identities"]["mock"].update(
                {
                    "image_ref": "registry.example/mock@sha256:" + "0" * 64,
                    "repo_digest": "registry.example/mock@sha256:" + "0" * 64,
                }
            ),
        }
        for label, mutate in mutations.items():
            value = valid_run_config()
            mutate(value)
            with self.subTest(label=label), self.assertRaises(ContractError):
                validate_run_config(value)
        with self.assertRaises(ContractError):
            build_execution_plan(manifest(), 1205, 11)

    def test_machine_evidence_rejects_execution_infra_and_sandbox_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, baseline, results = evidence_files(Path(directory))
            mutations = {
                "third_party_execution": lambda value: value.__setitem__(
                    "third_party_code_executions", 1
                ),
                "infrastructure_error": lambda value: value[
                    "infrastructure_errors"
                ].append("network"),
                "policy_identity": lambda value: value["identities"]["runner"].__setitem__(
                    "policy_sha256", "e" * 64
                ),
                "capability_add": lambda value: value["cold_starts"][0][
                    "containers"
                ]["cpa"]["cap_add"].append("SYS_ADMIN"),
                "root_container_user": lambda value: value["cold_starts"][0][
                    "containers"
                ]["cpa"].__setitem__("user", "0:0"),
                "network_identity": lambda value: value["cold_starts"][0][
                    "network"
                ].__setitem__("name", "other-run-net"),
                "quick_check": lambda value: value["cold_starts"][0][
                    "sqlite"
                ].__setitem__("quick_check", "not ok"),
            }
            for label, mutate in mutations.items():
                value = copy.deepcopy(baseline)
                mutate(value)
                with self.subTest(label=label), self.assertRaises(ContractError):
                    validate_machine_evidence(source_manifest, value, results)

    def test_allow_and_block_side_effects_and_error_response_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, _, results = evidence_files(Path(directory))
            cases = {case["id"]: case for case in source_manifest["semantic_cases"]}
            rows = [json.loads(line) for line in results.read_text("utf-8").splitlines()]
            allow = next(row for row in rows if row["expected_action"] == "allow")
            blocked = next(
                row for row in rows if row["expected_action"] == "block_malicious_text"
            )
            mutations = {
                "allow_mock_zero": (allow, lambda row: row["side_effect_deltas"].__setitem__("mock", 0)),
                "block_mock_one": (blocked, lambda row: row["side_effect_deltas"].__setitem__("mock", 1)),
                "block_content_type": (
                    blocked,
                    lambda row: row["error_contract"].__setitem__(
                        "content_type", "application/json"
                    ),
                ),
                "block_no_store": (
                    blocked,
                    lambda row: row["error_contract"].__setitem__("no_store", False),
                ),
            }
            for label, (template, mutate) in mutations.items():
                row = copy.deepcopy(template)
                mutate(row)
                with self.subTest(label=label), self.assertRaises(ContractError):
                    validate_result(row, cases, label)

    def test_block_response_rejects_any_message_suffix_or_source_echo(self) -> None:
        headers = {
            "cache-control": "no-store",
            "content-type": "application/json; charset=utf-8",
            "x-content-type-options": "nosniff",
        }
        error = {
            "error": {
                "category": "credential_theft",
                "code": "cyber_abuse_guard_blocked",
                "message": BLOCK_REFUSAL_MESSAGE,
                "type": "policy_violation",
            }
        }
        exact = validate_block_response(canonical_bytes(error), headers)
        self.assertTrue(exact["schema_valid"])
        error["error"]["message"] += " NERV_COMPLETE_TEXT_CANARY"
        appended = validate_block_response(canonical_bytes(error), headers)
        self.assertFalse(appended["schema_valid"])

    def test_logical_request_identity_must_match_across_modes_and_cold_starts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, evidence, results = evidence_files(Path(directory))
            rows = [json.loads(line) for line in results.read_text("utf-8").splitlines()]
            target = next(
                row
                for row in rows
                if row["expected_action"] == "allow" and row["audit_event"] is None
            )
            target["request_sha256"] = digest("drifted-request")
            target["expected_audit_request_hash"] = "sha256:" + digest(
                "drifted-audit-request"
            )
            rewrite_results(evidence, results, rows)
            with self.assertRaises(ContractError):
                validate_machine_evidence(source_manifest, evidence, results)

    def test_evidence_is_cross_bound_to_the_canonical_run_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, baseline, _ = evidence_files(Path(directory))
            config, config_raw = config_bound_to_evidence(baseline)
            validate_run_config(config)
            validate_evidence_run_config(baseline, config, config_raw)

            run_drift = copy.deepcopy(baseline)
            run_config = copy.deepcopy(config)
            run_config["run"]["seed"] += 1
            run_raw = canonical_bytes(run_config) + b"\n"
            run_drift["identities"]["configuration"]["input_sha256"] = sha256_bytes(
                run_raw
            )
            with self.assertRaises(ContractError):
                validate_evidence_run_config(run_drift, run_config, run_raw)

            cpa_drift = copy.deepcopy(baseline)
            cpa_config = copy.deepcopy(config)
            cpa_config["identities"]["cpa"]["binary_sha256"] = digest("other-binary")
            cpa_raw = canonical_bytes(cpa_config) + b"\n"
            cpa_drift["identities"]["configuration"]["input_sha256"] = sha256_bytes(
                cpa_raw
            )
            with self.assertRaises(ContractError):
                validate_evidence_run_config(cpa_drift, cpa_config, cpa_raw)

    def test_evidence_cli_requires_the_run_config_argument(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            validator_cli.parser().parse_args(
                [
                    "evidence",
                    "--manifest",
                    "manifest.json",
                    "--evidence",
                    "machine-evidence.json",
                    "--results",
                    "results.jsonl",
                ]
            )
        parsed = validator_cli.parser().parse_args(
            [
                "evidence",
                "--manifest",
                "manifest.json",
                "--evidence",
                "machine-evidence.json",
                "--results",
                "results.jsonl",
                "--run-config",
                "run-config.json",
            ]
        )
        self.assertEqual(parsed.run_config, Path("run-config.json"))

    def test_evidence_cli_rejects_non_object_without_traceback(self) -> None:
        cases = (
            ([], "machine evidence must be a JSON object"),
            (
                {"identities": []},
                "machine evidence.identities must be a JSON object",
            ),
        )
        for evidence, expected in cases:
            with self.subTest(expected=expected):
                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        validator_cli,
                        "load_json_file",
                        side_effect=[{"placeholder": True}, evidence],
                    ),
                    mock.patch.object(
                        validator_cli, "validate_corpus_manifest", return_value={}
                    ),
                    mock.patch.object(validator_cli, "bind_policy"),
                    contextlib.redirect_stderr(stderr),
                ):
                    result = validator_cli.main(
                        [
                            "evidence",
                            "--manifest",
                            "manifest.json",
                            "--evidence",
                            "machine-evidence.json",
                            "--results",
                            "results.jsonl",
                            "--run-config",
                            "run-config.json",
                        ]
                    )
                self.assertEqual(result, 2)
                self.assertIn(expected, stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())


class RunnerFailureSafetyTests(unittest.TestCase):
    def test_mock_image_source_is_verified_before_execution(self) -> None:
        expected_source = (TOOL / "counted_mock.py").read_bytes()
        expected_sha = sha256_bytes(expected_source)
        image_id = "sha256:" + "b" * 64
        image_ref = "registry.example/mock@sha256:" + "8" * 64

        class MockImageDocker:
            def __init__(self, source: bytes) -> None:
                self.source = source
                self.created = False
                self.commands: list[list[str]] = []

            def absent(self, kind: str, name: str) -> bool:
                self.assert_container(kind, name)
                return not self.created

            def inspect(self, kind: str, name: str) -> dict[str, Any]:
                self.assert_container(kind, name)
                return {
                    "Config": {
                        "Labels": {
                            run.LABEL_KEY: "unit-run",
                            run.ROLE_LABEL: "mock-source-verifier",
                        }
                    },
                    "HostConfig": {"NetworkMode": "none"},
                    "Image": image_id,
                    "State": {"Running": False},
                }

            def run(
                self, args: list[str], *, timeout: int, check: bool = True
            ) -> types.SimpleNamespace:
                del timeout, check
                self.commands.append(list(args))
                if args[0] == "create":
                    self.created = True
                elif args[0] == "cp":
                    Path(args[-1]).write_bytes(self.source)
                elif args[0] == "rm":
                    self.created = False
                else:  # pragma: no cover - the fake is deliberately closed
                    raise AssertionError(f"unexpected Docker command: {args}")
                return types.SimpleNamespace(returncode=0)

            @staticmethod
            def assert_container(kind: str, name: str) -> None:
                if kind != "container" or name != "unit-run-mock":
                    raise AssertionError(f"unexpected Docker identity: {kind} {name}")

        def mock_source_harness(
            docker: MockImageDocker, directory: str
        ) -> run.Harness:
            harness = object.__new__(run.Harness)
            harness.config = {
                "identities": {
                    "mock": {
                        "image_id": image_id,
                        "image_ref": image_ref,
                        "source_sha256": expected_sha,
                    }
                }
            }
            harness.docker = docker
            harness.evidence_dir = Path(directory)
            harness.mock_name = "unit-run-mock"
            harness.run_id = "unit-run"
            return harness

        for source, should_pass in (
            (expected_source, True),
            (expected_source + b"\n# drift", False),
        ):
            with self.subTest(should_pass=should_pass), tempfile.TemporaryDirectory() as directory:
                docker = MockImageDocker(source)
                harness = mock_source_harness(docker, directory)
                if should_pass:
                    harness.verify_mock_image_source()
                else:
                    with self.assertRaises(run.AuditFailure):
                        harness.verify_mock_image_source()
                self.assertFalse(docker.created)
                self.assertEqual([command[0] for command in docker.commands], ["create", "cp", "rm"])

        class CleanupIdentityDriftDocker(MockImageDocker):
            def __init__(self, source: bytes) -> None:
                super().__init__(source)
                self.inspect_calls = 0

            def inspect(self, kind: str, name: str) -> dict[str, Any]:
                value = super().inspect(kind, name)
                self.inspect_calls += 1
                if self.inspect_calls > 1:
                    value["Config"]["Labels"][run.ROLE_LABEL] = "drifted"
                return value

        with tempfile.TemporaryDirectory() as directory:
            docker = CleanupIdentityDriftDocker(expected_source)
            harness = mock_source_harness(docker, directory)
            with self.assertRaisesRegex(
                run.AuditFailure, "refusing cleanup of an unbound Mock source verifier"
            ):
                harness.verify_mock_image_source()
            self.assertEqual(list(Path(directory).iterdir()), [])

        class ImageDocker:
            def inspect(self, kind: str, identity: str) -> dict[str, Any]:
                self.kind = kind
                self.identity = identity
                return {
                    "Architecture": "amd64",
                    "Config": {
                        "Cmd": None,
                        "Entrypoint": ["python3", "/wrong.py"],
                        "Labels": {
                            "io.cyber-abuse-guard.mock-contract": run.MOCK_CONTRACT,
                            "io.cyber-abuse-guard.mock-source-sha256": expected_sha,
                        },
                    },
                    "Id": image_id,
                    "Os": "linux",
                    "RepoDigests": [image_ref],
                }

        with self.assertRaises(run.AuditFailure):
            run.image_identity(
                ImageDocker(),
                {
                    "image_id": image_id,
                    "image_ref": image_ref,
                    "repo_digest": image_ref,
                    "source_sha256": expected_sha,
                },
                "mock",
            )

    def test_emergency_cleanup_reports_uninspectable_residual_resources(self) -> None:
        class ResidualDocker:
            def __init__(self) -> None:
                self.absent_calls: list[tuple[str, str]] = []

            def absent(self, kind: str, name: str) -> bool:
                self.absent_calls.append((kind, name))
                return False

        docker = ResidualDocker()
        tracker = run.CleanupTracker(
            docker,
            "unit-run",
            "unit-run-cpa",
            "unit-run-mock",
            "unit-run-net",
        )
        with self.assertRaises(run.CleanupFailure) as raised:
            tracker.emergency()
        self.assertEqual(len(raised.exception.cleanup_error_id), 16)
        self.assertTrue(raised.exception.cleanup_error_id.strip("0"))
        self.assertGreaterEqual(docker.absent_calls.count(("container", "unit-run-cpa")), 3)
        self.assertGreaterEqual(docker.absent_calls.count(("container", "unit-run-mock")), 3)
        self.assertGreaterEqual(docker.absent_calls.count(("network", "unit-run-net")), 2)

    def test_emergency_cleanup_removes_every_exact_owned_resource(self) -> None:
        class StateDocker:
            def __init__(self) -> None:
                self.running = {"unit-run-cpa": True, "unit-run-mock": True}
                self.network_present = True

            def absent(self, kind: str, name: str) -> bool:
                if kind == "container":
                    return name not in self.running
                return not self.network_present

            def inspect(self, kind: str, name: str) -> dict[str, Any]:
                if kind == "container":
                    return {
                        "Config": {"Labels": {run.LABEL_KEY: "unit-run"}},
                        "State": {"Running": self.running[name]},
                    }
                return {
                    "Containers": {},
                    "Labels": {run.LABEL_KEY: "unit-run"},
                }

            def run(
                self, args: list[str], *, timeout: int, check: bool = True
            ) -> types.SimpleNamespace:
                del timeout, check
                if args[0] == "stop":
                    self.running[args[-1]] = False
                elif args[0] == "rm":
                    del self.running[args[-1]]
                elif args[:2] == ["network", "rm"]:
                    self.network_present = False
                else:  # pragma: no cover - the fake is deliberately closed
                    raise AssertionError(f"unexpected Docker command: {args}")
                return types.SimpleNamespace(returncode=0)

        docker = StateDocker()
        tracker = run.CleanupTracker(
            docker,
            "unit-run",
            "unit-run-cpa",
            "unit-run-mock",
            "unit-run-net",
        )
        tracker.emergency()
        self.assertEqual(docker.running, {})
        self.assertFalse(docker.network_present)
        self.assertEqual(len(tracker.resources), 3)

    def test_container_args_use_the_explicit_non_root_host_identity(self) -> None:
        harness = object.__new__(run.Harness)
        harness.network_name = "unit-run-net"
        harness.run_id = "unit-run"
        with (
            mock.patch.object(run.os, "getuid", return_value=1234, create=True),
            mock.patch.object(run.os, "getgid", return_value=5678, create=True),
        ):
            args = harness.common_container_args("cpa", "unit-run-cpa")
        user_index = args.index("--user") + 1
        self.assertEqual(args[user_index], "1234:5678")
        self.assertNotEqual(args[user_index], "0:0")
    def test_harness_finally_removes_validated_corpus_after_failure(self) -> None:
        source_manifest = manifest()
        canary = b"NERV_COMPLETE_TEXT_CANARY_MUST_NOT_PERSIST"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            acquisition = root / "acquisition"
            corpus = acquisition / "corpus"
            evidence_dir = root / "evidence"
            corpus.mkdir(parents=True)
            evidence_dir.mkdir(mode=0o700)
            evidence_dir.chmod(0o700)
            payloads: dict[str, bytes] = {}
            for case in source_manifest["semantic_cases"]:
                source = case["source"]
                relative = source["corpus_file"]
                payload = payloads.setdefault(
                    relative, canary + relative.encode("utf-8")
                )
                source["text_bytes"] = len(payload)
                source["text_sha256"] = sha256_bytes(payload)
                if source["archive_member"] is None:
                    source["source_sha256"] = source["text_sha256"]
                (acquisition / relative).write_bytes(payload)
            root_info = acquisition.stat()
            corpus_info = corpus.stat()
            source_manifest["filesystem_identity"] = {
                "acquisition_root": {
                    "device": root_info.st_dev,
                    "inode": root_info.st_ino,
                },
                "corpus_directory": {
                    "device": corpus_info.st_dev,
                    "inode": corpus_info.st_ino,
                },
            }
            config = {
                "paths": {
                    "corpus_manifest": str(acquisition / "corpus-manifest.json")
                },
                "run": {"cold_start_count": 3, "run_id": "unit-run", "seed": 1205},
            }
            evidence_binding = run.BoundEvidenceDirectory(evidence_dir)
            self.addCleanup(evidence_binding.close)
            harness = run.Harness(
                config,
                b"{}\n",
                source_manifest,
                canonical_bytes(source_manifest) + b"\n",
                evidence_binding,
                object(),  # The failure occurs before any Docker operation.
            )

            def fail_after_validation() -> None:
                harness.bound_corpus = run.BoundCorpus(
                    acquisition,
                    source_manifest["filesystem_identity"],
                    "unit-test corpus",
                )
                harness.bound_corpus.verify_manifest_files(source_manifest)
                harness.corpus_validated = True
                raise run.AuditFailure("synthetic post-validation failure")

            harness.verify_static_inputs = fail_after_validation  # type: ignore[method-assign]
            harness.cleanup.emergency = mock.Mock()  # type: ignore[method-assign]
            with self.assertRaises(run.AuditFailure):
                harness.execute(STAMP)
            self.assertFalse(corpus.exists())
            self.assertEqual(
                harness.cleanup.text_files_removed, source_manifest["source_count"]
            )
            self.assertFalse(harness.cleanup.text_retained)
            self.assertNotIn(canary, canonical_bytes(source_manifest))

    def test_preexisting_evidence_directory_is_never_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "existing-evidence"
            existing.mkdir()
            marker = existing / "operator-owned.txt"
            marker.write_text("preserve", encoding="utf-8")
            policy_raw = b"{}\n"
            policy_sha256 = sha256_bytes(policy_raw)
            config = {
                "paths": {
                    "corpus_manifest": str(root / "acquisition" / "corpus-manifest.json"),
                    "evidence_directory": str(existing),
                },
                "policy_sha256": policy_sha256,
            }
            source_manifest = manifest()
            source_manifest["policy_sha256"] = policy_sha256
            with (
                mock.patch.object(
                    run,
                    "load_canonical",
                    side_effect=[
                        (config, b"{}\n"),
                        (source_manifest, canonical_bytes(source_manifest) + b"\n"),
                    ],
                ),
                mock.patch.object(run, "validate_run_config", return_value=config),
                mock.patch.object(run, "require_private_directory"),
                mock.patch.object(
                    run, "validate_corpus_manifest", return_value=source_manifest
                ),
                mock.patch.object(run, "read_regular_bytes", return_value=policy_raw),
                mock.patch.object(run, "validate_policy", return_value={}),
                mock.patch.object(run, "validate_manifest_policy"),
                mock.patch.object(
                    run.BoundEvidenceDirectory,
                    "create",
                    wraps=run.BoundEvidenceDirectory.create,
                ) as create_evidence,
                mock.patch.object(run, "remove_manifest_corpus", return_value=(0, False)),
                mock.patch.object(run, "write_json") as write_json,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(run.main(["--config", str(root / "config.json")]), 2)
            create_evidence.assert_called_once_with(existing)
            write_json.assert_not_called()
            self.assertEqual([path.name for path in existing.iterdir()], [marker.name])
            self.assertEqual(marker.read_text("utf-8"), "preserve")

    def test_main_aggregates_harness_and_outer_cleanup_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "new-evidence"
            source_manifest = manifest()
            policy_raw = b"{}\n"
            policy_sha256 = sha256_bytes(policy_raw)
            source_manifest["policy_sha256"] = policy_sha256
            config = {
                "paths": {
                    "corpus_manifest": str(
                        root / "acquisition" / "corpus-manifest.json"
                    ),
                    "evidence_directory": str(evidence),
                },
                "policy_sha256": policy_sha256,
            }
            primary = run.CleanupFailure(["harness:RuntimeError"])
            outer = run.CleanupFailure(["corpus:OSError"])
            harness = mock.Mock()
            harness.execute.side_effect = primary
            harness.corpus_cleanup_completed = False
            harness.failure_stage = "cpa_readiness"
            harness.readiness_state_sha256 = "a" * 64

            with (
                mock.patch.object(
                    run,
                    "load_canonical",
                    side_effect=[
                        (config, b"{}\n"),
                        (
                            source_manifest,
                            canonical_bytes(source_manifest) + b"\n",
                        ),
                    ],
                ),
                mock.patch.object(run, "validate_run_config", return_value=config),
                mock.patch.object(run, "require_private_directory"),
                mock.patch.object(
                    run, "validate_corpus_manifest", return_value=source_manifest
                ),
                mock.patch.object(run, "read_regular_bytes", return_value=policy_raw),
                mock.patch.object(run, "validate_policy", return_value={}),
                mock.patch.object(run, "validate_manifest_policy"),
                mock.patch.object(run, "Docker", return_value=object()),
                mock.patch.object(run, "Harness", return_value=harness),
                mock.patch.object(
                    run, "remove_manifest_corpus", side_effect=outer
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    run.main(["--config", str(root / "run-config.json")]), 2
                )

            failure = json.loads((evidence / "failure.json").read_text("utf-8"))
            expected_cleanup_id = sha256_bytes(
                canonical_bytes(
                    sorted({primary.cleanup_error_id, outer.cleanup_error_id})
                )
            )[:16]
            self.assertEqual(failure["cleanup_error_id"], expected_cleanup_id)
            self.assertEqual(failure["failure_stage"], "cpa_readiness")
            self.assertFalse(failure["machine_evidence_emitted"])
            self.assertEqual(failure["state_sha256"], "a" * 64)
            self.assertEqual(failure["third_party_code_executions"], 0)


if __name__ == "__main__":
    unittest.main()
