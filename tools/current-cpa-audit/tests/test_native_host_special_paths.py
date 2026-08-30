from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence
from unittest import mock


HERE = Path(__file__).resolve().parent
TOOL_DIR = HERE.parent
sys.path.insert(0, str(TOOL_DIR))

from audit_contract import (  # noqa: E402
    CAG_SO_NAME,
    CAG_SOURCE_VERSION,
    CANDIDATE_ARTIFACT_NAME,
    CANDIDATE_MANIFEST_NAME,
    CANDIDATE_MANIFEST_SCHEMA,
    CANDIDATE_MANIFEST_STATUS,
    CANDIDATE_REPOSITORY,
    CANDIDATE_WORKFLOW_NAME,
    CANDIDATE_WORKFLOW_PATH,
    ContractError,
    canonical_bytes,
    sha256_bytes,
)
import native_host_special_paths as native  # noqa: E402


try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None  # type: ignore[assignment]


NOW = datetime(2026, 8, 9, 12, 0, 0, tzinfo=timezone.utc)
RUNTIME = {"go_version": native.GO_VERSION, "platform": native.PLATFORM}
ARTIFACT_ID = 987654321
ARTIFACT_DIGEST = "sha256:" + "d" * 64
ARTIFACT_SIZE = 123456
SECRET_OUTPUT = "REQUEST-CONTENT-MUST-NOT-ENTER-REPORT"
STORE_INSTALL_PATH = f"/tmp/cag-host-evidence/plugins/linux/amd64/{CAG_SO_NAME}"


def _run_git(repository: Path, *arguments: str) -> str:
    environment = os.environ.copy()
    for variable in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
    ):
        environment.pop(variable, None)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "ALL_PROXY": "",
        }
    )
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        env=environment,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"git {' '.join(arguments)} failed with {result.returncode}: {result.stderr}"
        )
    return result.stdout.strip()


def _json_event(
    action: str, *, test: str | None = None, package: str | None = None
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "Action": action,
        "Package": native.PACKAGE if package is None else package,
        "Time": "2026-08-09T12:00:00Z",
    }
    if test is not None:
        event["Test"] = test
    return event


def store_receipt_output(store_archive_sha256: str) -> str:
    return (
        "    host_integration_test.go:4581: "
        "CPA v7.2.145 Store installed real archive "
        f"sha256={store_archive_sha256} path={STORE_INSTALL_PATH}\n"
    )


def passing_events(
    *, store_archive_sha256: str, include_secret_output: bool = True
) -> list[dict[str, Any]]:
    events = [_json_event("start"), _json_event("run", test=native.TOP_LEVEL_TEST)]
    receipt = _json_event("output", test=native.TOP_LEVEL_TEST)
    receipt["Output"] = store_receipt_output(store_archive_sha256)
    events.append(receipt)
    for _, suffix in native.CRITICAL_SUBTESTS:
        name = f"{native.TOP_LEVEL_TEST}/{suffix}"
        events.extend((_json_event("run", test=name), _json_event("pass", test=name)))
    if include_secret_output:
        output = _json_event("output", test=native.TOP_LEVEL_TEST)
        output["Output"] = SECRET_OUTPUT + "\n"
        events.append(output)
    events.extend((_json_event("pass", test=native.TOP_LEVEL_TEST), _json_event("pass")))
    return events


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.checkout = (self.root / "checkout").resolve()
        self.candidate = (self.root / "candidate").resolve()
        self.empty_hooks = (self.root / "empty-hooks").resolve()
        self.log_path = (self.root / "go-test.jsonl").resolve()
        self.report_path = (self.root / native.REPORT_NAME).resolve()
        self.checkout.mkdir()
        self.empty_hooks.mkdir()
        source = self.checkout / native.TEST_SOURCE
        source.parent.mkdir(parents=True)
        source.write_text(
            "package integration\n\nfunc TestCPAPluginHostBlocksBeforeUpstream() {}\n",
            encoding="utf-8",
            newline="\n",
        )
        _run_git(self.checkout, "init")
        _run_git(self.checkout, "config", "user.email", "fixture@example.invalid")
        _run_git(self.checkout, "config", "user.name", "Native Host Fixture")
        _run_git(self.checkout, "config", "commit.gpgsign", "false")
        _run_git(
            self.checkout, "config", "core.hooksPath", str(self.empty_hooks)
        )
        _run_git(self.checkout, "add", "--", native.TEST_SOURCE)
        _run_git(self.checkout, "commit", "-m", "fixture")
        self.commit = _run_git(self.checkout, "rev-parse", "HEAD^{commit}").lower()
        self.tree = _run_git(self.checkout, "rev-parse", "HEAD^{tree}").lower()
        self.candidate.mkdir()
        self._write_candidate()
        self.write_events(self.passing_events())

    @property
    def manifest_path(self) -> Path:
        return (self.candidate / CANDIDATE_MANIFEST_NAME).resolve()

    def common(self) -> dict[str, Any]:
        return {
            "artifact_digest": ARTIFACT_DIGEST,
            "artifact_id": ARTIFACT_ID,
            "artifact_name": CANDIDATE_ARTIFACT_NAME,
            "artifact_size": ARTIFACT_SIZE,
            "candidate_manifest": self.manifest_path,
            "checkout": self.checkout,
            "go_test_jsonl": self.log_path,
        }

    def build(self) -> dict[str, Any]:
        return native.build_report(
            **self.common(), generated_at=NOW, runtime=RUNTIME
        )

    def passing_events(
        self, *, include_secret_output: bool = True
    ) -> list[dict[str, Any]]:
        return passing_events(
            store_archive_sha256=self.store_archive_sha256,
            include_secret_output=include_secret_output,
        )

    def parse_log(self) -> dict[str, Any]:
        return native.parse_go_test_log(
            self.log_path,
            expected_store_archive_sha256=self.store_archive_sha256,
        )

    def validate_bundle(self, **overrides: Any) -> dict[str, Any]:
        arguments = self.common()
        arguments.update(overrides)
        return native.validate_bundle(
            report_path=self.report_path, runtime=RUNTIME, **arguments
        )

    def write_events(self, events: Sequence[dict[str, Any]]) -> None:
        raw = b"\n".join(canonical_bytes(event) for event in events) + b"\n"
        self.log_path.write_bytes(raw)

    def write_report(self, report: dict[str, Any]) -> None:
        self.report_path.write_bytes(canonical_bytes(report) + b"\n")
        os.chmod(self.report_path, 0o600)

    def manifest(self) -> dict[str, Any]:
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def write_manifest(self, manifest: dict[str, Any]) -> None:
        self.manifest_path.write_bytes(canonical_bytes(manifest) + b"\n")

    def reseal_manifest(self) -> None:
        manifest = self.manifest()
        manifest["artifacts"] = [
            {
                "bytes": path.stat().st_size,
                "name": name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for name in native.EXPECTED_CANDIDATE_FILES
            if name != CANDIDATE_MANIFEST_NAME
            for path in [self.candidate / name]
        ]
        self.write_manifest(manifest)

    def _write_candidate(self) -> None:
        so_raw = b"fixture linux amd64 shared object bytes\n"
        so_sha = sha256_bytes(so_raw)
        (self.candidate / CAG_SO_NAME).write_bytes(so_raw)
        (self.candidate / (CAG_SO_NAME + ".sha256")).write_text(
            f"{so_sha}  {CAG_SO_NAME}\n", encoding="ascii", newline="\n"
        )

        zip_name = f"cyber-abuse-guard_{CAG_SOURCE_VERSION}_linux_amd64.zip"
        with zipfile.ZipFile(self.candidate / zip_name, "w", zipfile.ZIP_STORED) as archive:
            member = zipfile.ZipInfo(CAG_SO_NAME)
            member.external_attr = 0o100700 << 16
            archive.writestr(member, so_raw)
        self.store_archive_sha256 = sha256_bytes(
            (self.candidate / zip_name).read_bytes()
        )

        metadata = {
            "cgo_enabled": True,
            "commit": self.commit,
            "dirty": False,
            "goarch": "amd64",
            "goos": "linux",
            "schema_version": 4,
            "source_version": CAG_SOURCE_VERSION,
            "tree": self.tree,
            "version": CAG_SOURCE_VERSION,
        }
        (self.candidate / "build-metadata.json").write_bytes(
            canonical_bytes(metadata) + b"\n"
        )
        ruleset_raw = canonical_bytes({"plugin_version": CAG_SOURCE_VERSION}) + b"\n"
        (self.candidate / "ruleset-manifest.json").write_bytes(ruleset_raw)
        (self.candidate / "ruleset.sha256").write_text(
            f"{sha256_bytes(ruleset_raw)}  ruleset-manifest.json\n",
            encoding="ascii",
            newline="\n",
        )
        sbom = {
            "metadata": {
                "component": {
                    "properties": [
                        {"name": "cag:source:git-commit", "value": self.commit},
                        {"name": "cag:source:git-tree", "value": self.tree},
                        {"name": "cag:build:kind", "value": "candidate"},
                    ]
                }
            }
        }
        (self.candidate / "sbom.cdx.json").write_bytes(canonical_bytes(sbom) + b"\n")

        checksummed = sorted(
            set(native.EXPECTED_CANDIDATE_FILES)
            - {CANDIDATE_MANIFEST_NAME, "checksums.txt"}
        )
        checksums = "".join(
            f"{hashlib.sha256((self.candidate / name).read_bytes()).hexdigest()}  {name}\n"
            for name in checksummed
        )
        (self.candidate / "checksums.txt").write_text(
            checksums, encoding="ascii", newline="\n"
        )

        artifacts = []
        for name in native.EXPECTED_CANDIDATE_FILES:
            if name == CANDIDATE_MANIFEST_NAME:
                continue
            raw = (self.candidate / name).read_bytes()
            artifacts.append(
                {"bytes": len(raw), "name": name, "sha256": sha256_bytes(raw)}
            )
        manifest = {
            "artifacts": artifacts,
            "commit": self.commit,
            "dirty": False,
            "event": "push",
            "head_branch": "main",
            "head_sha": self.commit,
            "repository": CANDIDATE_REPOSITORY,
            "run_attempt": "1",
            "run_id": "123456789",
            "schema": CANDIDATE_MANIFEST_SCHEMA,
            "status": CANDIDATE_MANIFEST_STATUS,
            "tree": self.tree,
            "version": CAG_SOURCE_VERSION,
            "workflow_name": CANDIDATE_WORKFLOW_NAME,
            "workflow_path": CANDIDATE_WORKFLOW_PATH,
        }
        self.write_manifest(manifest)


class NativeHostSpecialPathsTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self) -> Iterator[Fixture]:
        with tempfile.TemporaryDirectory() as directory:
            yield Fixture(Path(directory))

    def test_run_git_ignores_parent_repository_environment(self) -> None:
        with self.fixture() as fixture:
            decoy = (fixture.root / "decoy").resolve()
            decoy.mkdir()
            _run_git(decoy, "init")
            _run_git(decoy, "config", "isolation.owner", "decoy")

            parent_environment = {
                "GIT_DIR": str(decoy / ".git"),
                "GIT_WORK_TREE": str(decoy),
                "GIT_INDEX_FILE": str(decoy / ".git" / "index"),
                "GIT_COMMON_DIR": str(decoy / ".git"),
                "GIT_OBJECT_DIRECTORY": str(decoy / ".git" / "objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(decoy / ".git" / "objects"),
                "GIT_NAMESPACE": "parent-environment",
            }
            with mock.patch.dict(os.environ, parent_environment, clear=False):
                actual_root = Path(
                    _run_git(fixture.checkout, "rev-parse", "--show-toplevel")
                ).resolve()
                _run_git(
                    fixture.checkout, "config", "isolation.owner", "fixture"
                )

            self.assertEqual(actual_root, fixture.checkout)
            self.assertEqual(
                _run_git(fixture.checkout, "config", "--get", "isolation.owner"),
                "fixture",
            )
            self.assertEqual(
                _run_git(decoy, "config", "--get", "isolation.owner"), "decoy"
            )

    def test_pack_validate_schema_and_no_output_copy(self) -> None:
        with self.fixture() as fixture:
            report = fixture.build()
            self.assertEqual(report["status"], native.STATUS)
            self.assertEqual(report["execution"]["required_test_count"], 36)
            self.assertEqual(len(report["execution"]["critical_tests"]), 35)
            self.assertEqual(
                report["execution"]["store_install"],
                {
                    "archive_name": native.STORE_ZIP_NAME,
                    "archive_sha256": fixture.store_archive_sha256,
                    "receipt_count": 1,
                    "receipt_sha256": sha256_bytes(
                        store_receipt_output(fixture.store_archive_sha256).encode(
                            "utf-8"
                        )
                    ),
                    "required": True,
                    "target_name": CAG_SO_NAME,
                },
            )
            self.assertNotIn(SECRET_OUTPUT.encode(), canonical_bytes(report))
            self.assertNotIn(STORE_INSTALL_PATH.encode(), canonical_bytes(report))
            native.write_exclusive(fixture.report_path, report)
            self.assertEqual(native.load_report(fixture.report_path)[0], report)
            self.assertEqual(fixture.validate_bundle(), report)
            if os.name == "posix":
                mode = stat.S_IMODE(fixture.report_path.stat().st_mode)
                self.assertEqual(mode, 0o600)

            if Draft202012Validator is not None:
                schema = json.loads(native.SCHEMA_PATH.read_text(encoding="utf-8"))
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(schema).validate(report)

    def test_cli_pack_and_validate_emit_hash_only_summary(self) -> None:
        with self.fixture() as fixture:
            common = [
                "--candidate-manifest",
                str(fixture.manifest_path),
                "--candidate-artifact-id",
                str(ARTIFACT_ID),
                "--candidate-artifact-name",
                CANDIDATE_ARTIFACT_NAME,
                "--candidate-artifact-digest",
                ARTIFACT_DIGEST,
                "--candidate-artifact-size",
                str(ARTIFACT_SIZE),
                "--go-test-jsonl",
                str(fixture.log_path),
                "--checkout",
                str(fixture.checkout),
            ]
            with mock.patch.object(native, "live_runtime_identity", return_value=RUNTIME):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(
                        native.main(["pack", *common, "--output", str(fixture.report_path)]),
                        0,
                    )
                summary = json.loads(stdout.getvalue())
                self.assertEqual(
                    set(summary), {"commit", "report_sha256", "status", "valid"}
                )
                self.assertNotIn(SECRET_OUTPUT, stdout.getvalue())

                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(
                        native.main(
                            ["validate", *common, "--report", str(fixture.report_path)]
                        ),
                        0,
                    )
                self.assertEqual(json.loads(stdout.getvalue()), summary)

                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        native,
                        "live_runtime_identity",
                        side_effect=subprocess.TimeoutExpired(["go", "env"], 30),
                    ),
                    contextlib.redirect_stderr(stderr),
                ):
                    self.assertEqual(
                        native.main(
                            [
                                "pack",
                                *common,
                                "--output",
                                str(fixture.root / "timeout-report.json"),
                            ]
                        ),
                        2,
                    )
                self.assertIn("TimeoutExpired", stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())

    def test_output_is_exclusive(self) -> None:
        with self.fixture() as fixture:
            report = fixture.build()
            native.write_exclusive(fixture.report_path, report)
            before = fixture.report_path.read_bytes()
            with self.assertRaises(ContractError):
                native.write_exclusive(fixture.report_path, report)
            self.assertEqual(fixture.report_path.read_bytes(), before)

    def test_output_replacement_before_postcheck_is_rejected(self) -> None:
        with self.fixture() as fixture:
            report = fixture.build()
            replacement = b"replacement must survive\n"
            original_verify = native._verify_created_output

            def replace_before_verify(
                path: Path, identity: dict[str, int], raw: bytes
            ) -> None:
                staged = path.with_name("replacement-before-verify")
                staged.write_bytes(replacement)
                os.replace(staged, path)
                original_verify(path, identity, raw)

            with mock.patch.object(
                native, "_verify_created_output", side_effect=replace_before_verify
            ), self.assertRaises(ContractError):
                native.write_exclusive(fixture.report_path, report)
            self.assertEqual(fixture.report_path.read_bytes(), replacement)

    def test_failure_preserves_created_output_for_explicit_cleanup(self) -> None:
        with self.fixture() as fixture:
            report = fixture.build()
            with mock.patch.object(
                native,
                "_verify_created_output",
                side_effect=ContractError("forced post-creation failure"),
            ), self.assertRaisesRegex(ContractError, "forced post-creation failure"):
                native.write_exclusive(fixture.report_path, report)
            self.assertEqual(
                fixture.report_path.read_bytes(), canonical_bytes(report) + b"\n"
            )

    def test_report_validator_rejects_noncanonical_and_internal_drift(self) -> None:
        with self.fixture() as fixture:
            report = fixture.build()
            fixture.report_path.write_text(
                json.dumps(report, indent=2), encoding="utf-8", newline="\n"
            )
            os.chmod(fixture.report_path, 0o600)
            with self.assertRaises(ContractError):
                native.load_report(fixture.report_path)

            mutations: list[tuple[str, Any]] = [
                (
                    "unknown top-level field",
                    lambda value: value.update({"request_output": SECRET_OUTPUT}),
                ),
                (
                    "manifest file coordinate",
                    lambda value: value["candidate"].update(
                        {"manifest_sha256": "a" * 64}
                    ),
                ),
                (
                    "SO coordinate",
                    lambda value: value["candidate"]["so"].update(
                        {"sha256": "b" * 64}
                    ),
                ),
                (
                    "critical order",
                    lambda value: value["execution"]["critical_tests"].reverse(),
                ),
                (
                    "Store archive coordinate",
                    lambda value: value["execution"]["store_install"].update(
                        {"archive_sha256": "a" * 64}
                    ),
                ),
                (
                    "Store receipt count",
                    lambda value: value["execution"]["store_install"].update(
                        {"receipt_count": 2}
                    ),
                ),
                (
                    "Store requirement downgrade",
                    lambda value: value["execution"]["store_install"].update(
                        {"required": False}
                    ),
                ),
                (
                    "artifact zero digest",
                    lambda value: value["candidate"]["artifact"].update(
                        {"digest": "sha256:" + "0" * 64}
                    ),
                ),
                (
                    "impossible event floor",
                    lambda value: value["test_log"].update({"event_count": 73}),
                ),
                (
                    "CPA C ABI boolean",
                    lambda value: value["cpa"].update({"c_abi": True}),
                ),
                (
                    "CPA RPC schema boolean",
                    lambda value: value["cpa"].update({"rpc_schema": True}),
                ),
                (
                    "CPA RPC schema string",
                    lambda value: value["cpa"].update({"rpc_schema": "3"}),
                ),
                (
                    "CPA RPC schema null",
                    lambda value: value["cpa"].update({"rpc_schema": None}),
                ),
                (
                    "CPA RPC schema missing",
                    lambda value: value["cpa"].pop("rpc_schema"),
                ),
            ]
            for label, mutate in mutations:
                with self.subTest(label=label):
                    changed = copy.deepcopy(report)
                    mutate(changed)
                    with self.assertRaises(ContractError):
                        native.validate_report(changed)

    def test_go_jsonl_parser_rejects_closed_contract_violations(self) -> None:
        with self.fixture() as fixture:
            base = fixture.passing_events()

            duplicate = canonical_bytes(base[0]).decode("utf-8").replace(
                '"Action":"start"', '"Action":"start","Action":"pass"'
            )
            fixture.log_path.write_text(
                duplicate + "\n" + "\n".join(
                    canonical_bytes(event).decode("utf-8") for event in base[1:]
                ) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaises(ContractError):
                fixture.parse_log()

            outside = "SomeOtherTest"
            mutations: list[tuple[str, list[dict[str, Any]]]] = []

            events = copy.deepcopy(base)
            events[0]["Action"] = "mystery"
            mutations.append(("unknown action", events))

            events = copy.deepcopy(base)
            events[0]["Package"] = native.PACKAGE + "/other"
            mutations.append(("extra package", events))

            for action in ("fail", "skip"):
                events = copy.deepcopy(base)
                events.insert(-1, _json_event(action, test=native.TOP_LEVEL_TEST))
                mutations.append((action.upper(), events))

            missing_name = f"{native.TOP_LEVEL_TEST}/{native.CRITICAL_SUBTESTS[0][1]}"
            events = [event for event in copy.deepcopy(base) if event.get("Test") != missing_name]
            mutations.append(("missing critical", events))

            events = copy.deepcopy(base)
            events.insert(-1, _json_event("run", test=missing_name))
            mutations.append(("duplicate run", events))

            events = copy.deepcopy(base)
            events.insert(-1, _json_event("pass", test=missing_name))
            mutations.append(("duplicate pass", events))

            mutations.append(("zero match", [_json_event("start"), _json_event("pass")]))

            events = copy.deepcopy(base)
            events[-1:-1] = [
                _json_event("run", test=outside),
                _json_event("pass", test=outside),
            ]
            mutations.append(("test outside selection", events))

            events = copy.deepcopy(base)
            events[0]["Unexpected"] = True
            mutations.append(("unknown event field", events))

            events = copy.deepcopy(base)
            events[0]["FailedBuild"] = native.PACKAGE
            mutations.append(("failed build", events))

            for label, events in mutations:
                with self.subTest(label=label):
                    fixture.write_events(events)
                    with self.assertRaises(ContractError):
                        fixture.parse_log()

            fixture.write_events(base)
            receipt_index = next(
                index
                for index, event in enumerate(base)
                if event.get("Output")
                == store_receipt_output(fixture.store_archive_sha256)
            )
            self.assertEqual(
                fixture.parse_log()["store_install"]["archive_sha256"],
                fixture.store_archive_sha256,
            )

            missing = copy.deepcopy(base)
            del missing[receipt_index]

            wrong_sha = copy.deepcopy(base)
            wrong_sha[receipt_index]["Output"] = store_receipt_output("e" * 64)

            duplicate = copy.deepcopy(base)
            duplicate.insert(receipt_index + 1, copy.deepcopy(duplicate[receipt_index]))

            fallback = copy.deepcopy(base)
            fallback_event = _json_event("output", test=native.TOP_LEVEL_TEST)
            fallback_event["Output"] = f"    {native.DIRECT_SO_FALLBACK_MARKER}\n"
            fallback.insert(receipt_index + 1, fallback_event)

            wrong_action = copy.deepcopy(base)
            wrong_action[receipt_index]["Action"] = "pass"

            wrong_owner = copy.deepcopy(base)
            wrong_owner[receipt_index]["Test"] = (
                f"{native.TOP_LEVEL_TEST}/{native.CRITICAL_SUBTESTS[0][1]}"
            )

            for label, events in (
                ("missing receipt", missing),
                ("wrong candidate ZIP SHA", wrong_sha),
                ("duplicate receipt", duplicate),
                ("direct-SO fallback", fallback),
                ("non-output receipt", wrong_action),
                ("receipt outside selected top-level test", wrong_owner),
            ):
                with self.subTest(label=label):
                    fixture.write_events(events)
                    with self.assertRaises(ContractError):
                        fixture.parse_log()

    def test_candidate_and_checkout_rejections(self) -> None:
        mutations = (
            "unknown candidate event",
            "extra directory entry",
            "candidate file drift",
            "build identity drift",
            "dirty checkout",
        )
        for label in mutations:
            with self.subTest(label=label), self.fixture() as fixture:
                if label == "unknown candidate event":
                    manifest = fixture.manifest()
                    manifest["event"] = "workflow_dispatch"
                    fixture.write_manifest(manifest)
                elif label == "extra directory entry":
                    (fixture.candidate / "unexpected.txt").write_text(
                        "unexpected", encoding="utf-8"
                    )
                elif label == "candidate file drift":
                    (fixture.candidate / CAG_SO_NAME).write_bytes(b"drift")
                elif label == "build identity drift":
                    metadata_path = fixture.candidate / "build-metadata.json"
                    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                    metadata["goarch"] = "arm64"
                    metadata_path.write_bytes(canonical_bytes(metadata) + b"\n")
                    fixture.reseal_manifest()
                elif label == "dirty checkout":
                    (fixture.checkout / "untracked.txt").write_text(
                        "dirty", encoding="utf-8"
                    )
                with self.assertRaises(ContractError):
                    fixture.build()

    def test_validate_rebinds_artifact_log_source_and_tool_identities(self) -> None:
        with self.fixture() as fixture:
            report = fixture.build()
            fixture.write_report(report)

            with self.assertRaises(ContractError):
                fixture.validate_bundle(artifact_size=ARTIFACT_SIZE + 1)
            with self.assertRaises(ContractError):
                fixture.validate_bundle(artifact_digest="sha256:" + "e" * 64)

            altered_events = fixture.passing_events()
            extra = _json_event("output", test=native.TOP_LEVEL_TEST)
            extra["Output"] = "harmless extra diagnostic\n"
            altered_events.insert(-2, extra)
            fixture.write_events(altered_events)
            with self.assertRaises(ContractError):
                fixture.validate_bundle()
            fixture.write_events(fixture.passing_events())

            changed = copy.deepcopy(report)
            changed["test_log"]["sha256"] = "a" * 64
            fixture.write_report(changed)
            with self.assertRaises(ContractError):
                fixture.validate_bundle()

            changed = copy.deepcopy(report)
            changed["test_source"]["sha256"] = "b" * 64
            fixture.write_report(changed)
            with self.assertRaises(ContractError):
                fixture.validate_bundle()

            changed = copy.deepcopy(report)
            changed["tool"]["source_sha256"] = "c" * 64
            fixture.write_report(changed)
            with self.assertRaises(ContractError):
                native.load_report(fixture.report_path)

            changed = copy.deepcopy(report)
            changed["execution"]["store_install"]["receipt_sha256"] = "f" * 64
            fixture.write_report(changed)
            with self.assertRaises(ContractError):
                fixture.validate_bundle()

    def test_candidate_checkout_commit_coordinate_drift_is_rejected(self) -> None:
        with self.fixture() as fixture:
            report = fixture.build()
            fixture.write_report(report)
            source = fixture.checkout / native.TEST_SOURCE
            source.write_text(
                source.read_text(encoding="utf-8") + "\n// committed drift\n",
                encoding="utf-8",
                newline="\n",
            )
            _run_git(fixture.checkout, "add", "--", native.TEST_SOURCE)
            _run_git(fixture.checkout, "commit", "-m", "source drift")
            with self.assertRaises(ContractError):
                fixture.validate_bundle()


if __name__ == "__main__":
    unittest.main()
