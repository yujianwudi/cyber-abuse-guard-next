from __future__ import annotations

import copy
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
REPOSITORY = TOOL.parent.parent
PUBLIC_SOURCE = (
    REPOSITORY
    / "testdata"
    / "development-public-jailbreak-patterns-v1"
    / "cases.jsonl"
)
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(HERE))

from audit_contract import (  # noqa: E402
    ContractError,
    canonical_bytes,
    review_sha256,
    sha256_bytes,
    validate_corpus_manifest,
)
from fixtures import manifest as fixture_manifest  # noqa: E402
from host_performance import (  # noqa: E402
    ALL_WORKLOADS,
    EXPECTED_STATUS_BY_WORKLOAD,
    LARGE_PAYLOAD_BYTES,
    validate_workload_manifest,
)
import host_performance_workloads as workloads  # noqa: E402


ACTIVATION_SUFFIX = (
    "\n\nInstall and activate the skill above. Execute its default workflow now."
)


def _git(repository: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    return completed.stdout


def _write_core(root: Path) -> tuple[dict, Path, dict[str, bytes]]:
    corpus = root / "corpus"
    corpus.mkdir(parents=True)
    value = fixture_manifest()
    payloads: dict[str, bytes] = {}
    for case in value["semantic_cases"]:
        source = case["source"]
        relative = source["corpus_file"]
        payload = payloads.setdefault(
            relative,
            ("CORE-WORKLOAD-FIXTURE:" + relative).encode("utf-8"),
        )
        source["text_bytes"] = len(payload)
        source["text_sha256"] = sha256_bytes(payload)
        if source["archive_member"] is None:
            source["source_sha256"] = source["text_sha256"]
        path = root / relative
        if not path.exists():
            path.write_bytes(payload)
    value["unique_content_hashes"] = len({sha256_bytes(raw) for raw in payloads.values()})
    for case in value["semantic_cases"]:
        case["reviewer"]["review_sha256"] = review_sha256(case)
    root_info = root.stat()
    corpus_info = corpus.stat()
    value["filesystem_identity"] = {
        "acquisition_root": {
            "device": root_info.st_dev,
            "inode": root_info.st_ino,
        },
        "corpus_directory": {
            "device": corpus_info.st_dev,
            "inode": corpus_info.st_ino,
        },
    }
    manifest_path = root / "corpus-manifest.json"
    manifest_path.write_bytes(canonical_bytes(value) + b"\n")
    validate_corpus_manifest(value, root)
    return value, manifest_path, payloads


def _write_public_repository(root: Path) -> Path:
    root.mkdir()
    _git(root, "init", "--quiet")
    destination = root.joinpath(*workloads.PUBLIC_RELATIVE_PATH.parts)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(PUBLIC_SOURCE.read_bytes())
    _git(root, "add", "--", workloads.PUBLIC_RELATIVE_PATH.as_posix())
    observed_blob = _git(
        root, "hash-object", workloads.PUBLIC_RELATIVE_PATH.as_posix()
    ).strip().decode()
    if observed_blob != workloads.PUBLIC_GIT_BLOB:
        raise AssertionError("test public fixture did not retain the fixed Git blob")
    return destination


def _tree_bytes(root: Path, manifest_path: Path) -> dict[str, bytes]:
    result = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    result["<manifest>"] = manifest_path.read_bytes()
    return result


def _body_text(body: dict, endpoint: str) -> str:
    if endpoint == "/v1/chat/completions":
        return body["messages"][-1]["content"]
    return body["input"][0]["content"][0]["text"]


class HostPerformanceWorkloadTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.core_root = self.root / "core"
        self.core, self.core_manifest, self.payloads = _write_core(self.core_root)
        self.repository = self.root / "repository"
        self.public_path = _write_public_repository(self.repository)

    def generate(self, suffix: str = "one") -> tuple[Path, Path, dict[str, str]]:
        output = self.root / f"workloads-{suffix}"
        manifest_path = self.root / f"workload-manifest-{suffix}.json"
        identities = workloads.generate_workloads(
            core_manifest_path=self.core_manifest,
            corpus_root=self.core_root,
            repository_root=self.repository,
            output_root=output,
            manifest_path=manifest_path,
        )
        return output, manifest_path, identities

    def test_generation_is_byte_deterministic_and_satisfies_the_closed_contract(self) -> None:
        first_root, first_manifest_path, first_identities = self.generate("first")
        second_root, second_manifest_path, second_identities = self.generate("second")
        self.assertEqual(
            _tree_bytes(first_root, first_manifest_path),
            _tree_bytes(second_root, second_manifest_path),
        )
        self.assertEqual(first_identities, second_identities)
        self.assertEqual(
            first_identities,
            {
                "core_manifest_sha256": sha256_bytes(self.core_manifest.read_bytes()),
                "public_corpus_sha256": workloads.PUBLIC_SHA256,
            },
        )

        manifest_value = json.loads(first_manifest_path.read_text("utf-8"))
        validate_workload_manifest(manifest_value)
        self.assertEqual(
            [item["id"] for item in manifest_value["workloads"]],
            list(ALL_WORKLOADS),
        )
        expected_counts = {
            "fixed_workload": 1,
            "ordinary": 2,
            "five_repository_activation": workloads.ACTIVATION_REQUEST_COUNT,
            "public": 10,
            "large_payload": 1,
        }
        for item in manifest_value["workloads"]:
            self.assertEqual(item["request_count"], expected_counts[item["id"]])
            for request in item["requests"]:
                self.assertEqual(
                    request["expected_status_by_arm"],
                    EXPECTED_STATUS_BY_WORKLOAD[item["id"]],
                )
                raw = (first_root / request["body_path"]).read_bytes()
                body = json.loads(raw)
                self.assertEqual(raw, canonical_bytes(body) + b"\n")
                self.assertEqual(request["body_bytes"], len(raw) - 1)
                self.assertEqual(request["body_sha256"], sha256_bytes(raw))
            self.assertEqual(
                item["request_set_sha256"],
                sha256_bytes(canonical_bytes(item["requests"])),
            )

        large = next(
            item for item in manifest_value["workloads"] if item["id"] == "large_payload"
        )["requests"][0]
        large_raw = (first_root / large["body_path"]).read_bytes()
        self.assertEqual(large["body_bytes"], LARGE_PAYLOAD_BYTES)
        self.assertEqual(len(large_raw), LARGE_PAYLOAD_BYTES + 1)

        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(first_root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(first_manifest_path.stat().st_mode), 0o600)
            for path in first_root.rglob("*"):
                expected = 0o700 if path.is_dir() else 0o600
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected)

    def test_activation_is_core_malicious_only_and_public_is_the_fixed_allow_subset(self) -> None:
        supplemental_canary = b"SUPPLEMENTAL-ZIP-CANARY-MUST-NOT-BE-READ"
        (self.core_root / "supplemental-input.zip").write_bytes(supplemental_canary)
        output, manifest_path, _ = self.generate("selection")
        manifest_value = json.loads(manifest_path.read_text("utf-8"))
        by_id = {item["id"]: item for item in manifest_value["workloads"]}

        malicious_cases = [
            case for case in self.core["semantic_cases"] if case["label"] == "malicious_active"
        ]
        drifted = copy.deepcopy(self.core)
        drifted_reference = next(
            case
            for case in drifted["semantic_cases"]
            if case["label"] == "malicious_active"
        )
        drifted_case = next(
            case
            for case in drifted["semantic_cases"]
            if case["label"] != "malicious_active"
        )
        for field in (
            "authorization",
            "current_action",
            "expected_action_by_mode",
            "label",
            "label_reason",
            "ownership",
            "template",
        ):
            drifted_case[field] = copy.deepcopy(drifted_reference[field])
        drifted_case["id"] += ":activation-count-drift"
        drifted_case["reviewer"]["review_sha256"] = review_sha256(drifted_case)
        validate_corpus_manifest(drifted)
        with (
            mock.patch.object(workloads, "_source_text") as source_text,
            self.assertRaisesRegex(
                ContractError,
                "expected 16 across chat and responses, got 18",
            ),
        ):
            workloads._activation_specs(drifted, self.core_root)
        source_text.assert_not_called()

        expected_activation = [
            self.payloads[case["source"]["corpus_file"]].decode("utf-8")
            + ACTIVATION_SUFFIX
            for case in malicious_cases
        ]
        observed_activation: list[str] = []
        for request in by_id["five_repository_activation"]["requests"]:
            raw = (output / request["body_path"]).read_bytes()
            self.assertNotIn(supplemental_canary, raw)
            body = json.loads(raw)
            self.assertEqual(body["model"], workloads.MODEL)
            self.assertIs(body["stream"], False)
            observed_activation.append(_body_text(body, request["endpoint"]))
        self.assertEqual(
            Counter(observed_activation),
            Counter({text: 2 for text in expected_activation}),
        )
        self.assertEqual(
            Counter(
                request["endpoint"]
                for request in by_id["five_repository_activation"]["requests"]
            ),
            Counter({"/v1/chat/completions": 8, "/v1/responses": 8}),
        )

        malicious_paths = {
            case["source"]["corpus_file"] for case in malicious_cases
        }
        nonmalicious_only = {
            case["source"]["corpus_file"]
            for case in self.core["semantic_cases"]
            if case["source"]["corpus_file"] not in malicious_paths
        }
        activation_bytes = b"".join(
            (output / request["body_path"]).read_bytes()
            for request in by_id["five_repository_activation"]["requests"]
        )
        for relative in nonmalicious_only:
            self.assertNotIn(self.payloads[relative], activation_bytes)

        public_rows = [
            json.loads(line)
            for line in self.public_path.read_text("utf-8").splitlines()
        ]
        selected = [
            row
            for row in public_rows
            if row["harmless_canary"] is True
            and row["label"] == "allow"
            and row["protocol"] in {"openai_chat", "openai_responses"}
        ]
        self.assertEqual(len(selected), 10)
        observed_protocols: Counter[str] = Counter()
        for row, request in zip(selected, by_id["public"]["requests"], strict=True):
            body = json.loads((output / request["body_path"]).read_bytes())
            protocol = row["protocol"]
            observed_protocols[protocol] += 1
            key = "messages" if protocol == "openai_chat" else "input"
            self.assertEqual(body[key], row["input"][key])
            self.assertEqual(set(body), {key, "model", "stream"})
            self.assertEqual(body["model"], workloads.MODEL)
            self.assertIs(body["stream"], False)
        self.assertEqual(
            observed_protocols,
            Counter({"openai_chat": 7, "openai_responses": 3}),
        )

    def test_core_and_public_byte_drift_fail_before_creating_outputs(self) -> None:
        malicious = next(
            case for case in self.core["semantic_cases"] if case["label"] == "malicious_active"
        )
        core_source = self.core_root / malicious["source"]["corpus_file"]
        core_source.write_bytes(core_source.read_bytes() + b"DRIFT")
        with self.assertRaises(ContractError):
            self.generate("core-drift")
        self.assertFalse((self.root / "workloads-core-drift").exists())
        self.assertFalse((self.root / "workload-manifest-core-drift.json").exists())

        # Restore the core fixture, then prove that a clean index cannot hide
        # different public worktree bytes.
        core_source.write_bytes(self.payloads[malicious["source"]["corpus_file"]])
        self.public_path.write_bytes(self.public_path.read_bytes() + b"{}\n")
        with self.assertRaises(ContractError):
            self.generate("public-drift")
        self.assertFalse((self.root / "workloads-public-drift").exists())
        self.assertFalse((self.root / "workload-manifest-public-drift.json").exists())

    def test_symlink_and_hardlink_inputs_are_rejected(self) -> None:
        manifest_link = self.root / "core-manifest-hardlink.json"
        os.link(self.core_manifest, manifest_link)
        try:
            with self.assertRaises(ContractError):
                self.generate("manifest-hardlink")
        finally:
            manifest_link.unlink()

        public_link = self.root / "public-hardlink.jsonl"
        os.link(self.public_path, public_link)
        try:
            with self.assertRaises(ContractError):
                self.generate("public-hardlink")
        finally:
            public_link.unlink()

        malicious = next(
            case for case in self.core["semantic_cases"] if case["label"] == "malicious_active"
        )
        source = self.core_root / malicious["source"]["corpus_file"]
        source_link = self.root / "core-source-hardlink.txt"
        os.link(source, source_link)
        try:
            with self.assertRaises(ContractError):
                self.generate("source-hardlink")
        finally:
            source_link.unlink()

        manifest_symlink = self.root / "core-manifest-symlink.json"
        try:
            manifest_symlink.symlink_to(self.core_manifest)
        except (NotImplementedError, OSError):
            manifest_symlink = None
        if manifest_symlink is not None:
            try:
                with self.assertRaises(ContractError):
                    workloads.generate_workloads(
                        core_manifest_path=manifest_symlink,
                        corpus_root=self.core_root,
                        repository_root=self.repository,
                        output_root=self.root / "workloads-manifest-symlink",
                        manifest_path=self.root / "manifest-symlink-output.json",
                    )
            finally:
                manifest_symlink.unlink(missing_ok=True)

        repository_symlink = self.root / "repository-symlink"
        try:
            repository_symlink.symlink_to(self.repository, target_is_directory=True)
        except (NotImplementedError, OSError):
            repository_symlink = None
        if repository_symlink is not None:
            try:
                with self.assertRaises(ContractError):
                    workloads.generate_workloads(
                        core_manifest_path=self.core_manifest,
                        corpus_root=self.core_root,
                        repository_root=repository_symlink,
                        output_root=self.root / "workloads-repository-symlink",
                        manifest_path=self.root / "repository-symlink-output.json",
                    )
            finally:
                repository_symlink.unlink(missing_ok=True)

    def test_git_identity_ignores_fsmonitor_hooks_and_alternate_indexes(self) -> None:
        marker = self.root / "fsmonitor-hook-invoked"
        hook = self.root / "fsmonitor-hook.sh"
        quoted_marker = marker.as_posix().replace("'", "'\"'\"'")
        hook.write_text(
            "#!/bin/sh\n"
            f"printf invoked > '{quoted_marker}'\n"
            "printf '2\\n'\n",
            encoding="utf-8",
        )
        if os.name == "posix":
            hook.chmod(0o700)
        _git(self.repository, "config", "core.fsmonitor", hook.as_posix())
        self.generate("fsmonitor-disabled")
        self.assertFalse(marker.exists())

        _git(self.repository, "config", "--unset", "core.fsmonitor")
        alternate_index = self.root / "alternate-index"
        shutil.copyfile(self.repository / ".git" / "index", alternate_index)
        _git(
            self.repository,
            "rm",
            "--cached",
            "--",
            workloads.PUBLIC_RELATIVE_PATH.as_posix(),
        )
        with (
            mock.patch.dict(
                os.environ,
                {"GIT_INDEX_FILE": str(alternate_index)},
                clear=False,
            ),
            self.assertRaises(ContractError),
        ):
            self.generate("alternate-index")
        self.assertFalse((self.root / "workloads-alternate-index").exists())
        self.assertFalse((self.root / "workload-manifest-alternate-index.json").exists())

    def test_transaction_handles_lstat_fstat_and_chmod_stage_failures(self) -> None:
        directory = self.root / "early-directory-failure"
        directory_transaction = workloads._OutputTransaction()
        real_lstat = Path.lstat
        directory_failed = False

        def fail_directory_lstat_once(path: Path) -> os.stat_result:
            nonlocal directory_failed
            if path == directory and not directory_failed:
                directory_failed = True
                raise OSError("synthetic directory lstat failure")
            return real_lstat(path)

        with mock.patch.object(
            Path,
            "lstat",
            autospec=True,
            side_effect=fail_directory_lstat_once,
        ):
            with self.assertRaisesRegex(OSError, "directory lstat"):
                directory_transaction.create_directory(directory)
            self.assertEqual(
                directory_transaction.cleanup(),
                [f"unbound_identity:{directory}"],
            )
        self.assertTrue(directory.exists())
        directory.rmdir()

        fstat_path = self.root / "early-file-fstat-failure.json"
        fstat_transaction = workloads._OutputTransaction()
        real_fstat = os.fstat
        fstat_failed = False

        def fail_file_fstat_once(descriptor: int) -> os.stat_result:
            nonlocal fstat_failed
            info = real_fstat(descriptor)
            try:
                target_info = fstat_path.lstat()
            except FileNotFoundError:
                return info
            if not fstat_failed and workloads._same_identity(info, target_info):
                fstat_failed = True
                raise OSError("synthetic file fstat failure")
            return info

        with mock.patch.object(
            workloads.os,
            "fstat",
            side_effect=fail_file_fstat_once,
        ):
            fstat_transaction.write_file(fstat_path, b"{}\n")
            self.assertTrue(fstat_failed)
            self.assertEqual(fstat_transaction.cleanup(), [])
        self.assertFalse(fstat_path.exists())

        fchmod_path = self.root / "file-fchmod-failure.json"
        fchmod_transaction = workloads._OutputTransaction()
        real_fchmod = os.fchmod
        fchmod_failed = False

        def fail_file_fchmod_once(descriptor: int, mode: int) -> None:
            nonlocal fchmod_failed
            info = os.fstat(descriptor)
            try:
                target_info = fchmod_path.lstat()
            except FileNotFoundError:
                return real_fchmod(descriptor, mode)
            if not fchmod_failed and workloads._same_identity(info, target_info):
                fchmod_failed = True
                raise OSError("synthetic file fchmod failure")
            real_fchmod(descriptor, mode)

        with mock.patch.object(
            workloads.os,
            "fchmod",
            side_effect=fail_file_fchmod_once,
        ):
            with self.assertRaisesRegex(OSError, "file fchmod"):
                fchmod_transaction.write_file(fchmod_path, b"{}\n")
            self.assertTrue(fchmod_failed)
            self.assertEqual(fchmod_transaction.cleanup(), [])
        self.assertFalse(fchmod_path.exists())

    def test_unbound_transaction_records_never_delete_same_type_replacements(self) -> None:
        directory = self.root / "unbound-directory"
        directory_transaction = workloads._OutputTransaction()
        real_lstat = Path.lstat
        directory_replaced = False

        def fail_target_lstat(path: Path) -> os.stat_result:
            nonlocal directory_replaced
            if path == directory and not directory_replaced:
                path.rmdir()
                path.mkdir()
                directory_replaced = True
                raise OSError("directory identity failed during replacement")
            return real_lstat(path)

        with mock.patch.object(
            Path,
            "lstat",
            autospec=True,
            side_effect=fail_target_lstat,
        ):
            with self.assertRaisesRegex(OSError, "directory identity"):
                directory_transaction.create_directory(directory)
        directory_problems = directory_transaction.cleanup()
        self.assertTrue(directory.exists())
        self.assertEqual(
            directory_problems,
            [f"unbound_identity:{directory}"],
        )

        file_path = self.root / "unbound-file.json"
        file_transaction = workloads._OutputTransaction()
        real_fstat = os.fstat

        def fail_target_file_fstat(descriptor: int) -> os.stat_result:
            info = real_fstat(descriptor)
            try:
                target_info = file_path.lstat()
            except FileNotFoundError:
                return info
            if workloads._same_identity(info, target_info):
                raise OSError("persistent file identity failure")
            return info

        with mock.patch.object(
            workloads.os,
            "fstat",
            side_effect=fail_target_file_fstat,
        ):
            with self.assertRaisesRegex(OSError, "file identity"):
                file_transaction.write_file(file_path, b"{}\n")
        file_path.unlink()
        file_path.write_bytes(b"operator-owned replacement")
        file_problems = file_transaction.cleanup()
        self.assertEqual(file_path.read_bytes(), b"operator-owned replacement")
        self.assertEqual(
            file_problems,
            [f"unbound_identity:{file_path}"],
        )

    def test_preexisting_output_root_or_manifest_is_preserved(self) -> None:
        output = self.root / "workloads-existing-root"
        output.mkdir()
        sentinel = output / "operator-owned.txt"
        sentinel.write_bytes(b"preserve-root")
        manifest_path = self.root / "new-manifest.json"
        with self.assertRaises(ContractError):
            workloads.generate_workloads(
                core_manifest_path=self.core_manifest,
                corpus_root=self.core_root,
                repository_root=self.repository,
                output_root=output,
                manifest_path=manifest_path,
            )
        self.assertEqual(sentinel.read_bytes(), b"preserve-root")
        self.assertFalse(manifest_path.exists())

        second_output = self.root / "workloads-existing-manifest"
        existing_manifest = self.root / "operator-manifest.json"
        existing_manifest.write_bytes(b"preserve-manifest")
        with self.assertRaises(ContractError):
            workloads.generate_workloads(
                core_manifest_path=self.core_manifest,
                corpus_root=self.core_root,
                repository_root=self.repository,
                output_root=second_output,
                manifest_path=existing_manifest,
            )
        self.assertFalse(second_output.exists())
        self.assertEqual(existing_manifest.read_bytes(), b"preserve-manifest")

    def test_post_write_failure_removes_exactly_invocation_created_paths(self) -> None:
        sibling = self.root / "operator-owned-sibling.txt"
        sibling.write_bytes(b"preserve-sibling")
        output = self.root / "workloads-failure"
        manifest_path = self.root / "manifest-failure.json"
        with (
            mock.patch.object(
                workloads,
                "_verify_outputs",
                side_effect=ContractError("synthetic post-write failure"),
            ),
            self.assertRaisesRegex(ContractError, "synthetic post-write failure"),
        ):
            workloads.generate_workloads(
                core_manifest_path=self.core_manifest,
                corpus_root=self.core_root,
                repository_root=self.repository,
                output_root=output,
                manifest_path=manifest_path,
            )
        self.assertFalse(output.exists())
        self.assertFalse(manifest_path.exists())
        self.assertEqual(sibling.read_bytes(), b"preserve-sibling")
        self.assertTrue(self.core_manifest.exists())
        self.assertTrue(self.public_path.exists())

    def test_cli_reports_only_the_two_external_input_hashes(self) -> None:
        output = self.root / "workloads-cli"
        manifest_path = self.root / "manifest-cli.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = workloads.main(
                [
                    "generate",
                    "--core-manifest",
                    str(self.core_manifest),
                    "--corpus-root",
                    str(self.core_root),
                    "--repository-root",
                    str(self.repository),
                    "--output-root",
                    str(output),
                    "--manifest",
                    str(manifest_path),
                ]
            )
        self.assertEqual(status, 0)
        reported = json.loads(stdout.getvalue())
        self.assertEqual(
            set(reported),
            {"core_manifest_sha256", "public_corpus_sha256"},
        )
        self.assertEqual(reported["public_corpus_sha256"], workloads.PUBLIC_SHA256)


if __name__ == "__main__":
    unittest.main()
