#!/usr/bin/env python3

from __future__ import annotations

import argparse
from contextlib import ExitStack
import copy
from email.message import Message
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import warnings
import zipfile

from cag_round9_eval_broker import (
    ARTIFACT_NAMES,
    CORPUS_ARCHIVE_NAMES,
    HOST_WORKFLOW,
    HOST_WORKFLOW_NAME,
    PHASE1_WORKFLOW_NAME,
    RELEASE_WORKFLOW,
    RULESET_PATHS,
    ContractError,
    GitHubClient,
    apply_candidate_identity_input,
    abort_verified_partial_ledger,
    candidate_identity,
    canonical_ed25519_public_spki,
    evaluator_identity,
    execution_identity,
    evaluate_once,
    ledger_event_payload,
    main as broker_main,
    minimal_subprocess_env,
    parser as broker_parser,
    run_external_evaluator,
    safe_extract_corpus,
    safe_extract_public_development_corpus,
    safe_extract_zip,
    validate_external_aggregate,
    validate_dispatch,
    validate_phase1_build_metadata,
    validate_phase1_release_manifest,
    validate_phase1_ruleset_manifest,
    validate_signing_key_material,
    verify_ledger_ruleset,
    verify_remote_identity,
)
from round9_eval_core import (
    FIXED_NETWORK_BINDING,
    FIXED_PHASE_PROTOCOL,
    canonical_bytes,
    sha256_file,
)
from round9_eval_test_fixtures import (
    decision_audit,
    development_evidence,
    public_counted_mock,
    runtime_checks,
)


class FakeHTTPResponse:
    def __init__(self, status: int, raw: bytes = b"", headers: Message | None = None):
        self.status = status
        self._raw = raw
        self.headers = headers or Message()

    def __enter__(self) -> "FakeHTTPResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _maximum: int = -1) -> bytes:
        return self._raw


class BrokerIdentityContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.args = argparse.Namespace(
            repository="example/cyber-abuse-guard",
            tag="v0.16-rc.4",
            tag_object_sha="1" * 40,
            commit="2" * 40,
            tree="3" * 40,
            phase1_run_id=101,
            phase1_run_attempt=1,
            phase1_artifact_id=202,
            phase1_artifact_digest="sha256:" + "4" * 64,
            so_sha256="5" * 64,
            classifier_policy_version="classifier-policy-v8",
            classifier_policy_sha256="6" * 64,
            ruleset_version="1.0.10",
            ruleset_sha256="7" * 64,
            ruleset_manifest_sha256="8" * 64,
            build_metadata_sha256="9" * 64,
            release_manifest_sha256="a" * 64,
            challenge="b" * 64,
            workflow_run_id=303,
            workflow_run_attempt=1,
            dispatch_ref="refs/tags/v0.16-rc.4",
            dispatch_sha="2" * 40,
            workflow_ref=(
                "example/cyber-abuse-guard/"
                ".github/workflows/round9-host-validation.yml@refs/tags/v0.16-rc.4"
            ),
            workflow_sha="2" * 40,
        )

    @staticmethod
    def public_corpus_root() -> Path:
        return Path(__file__).resolve().parents[2] / "testdata/round9-public-adversarial-v13"

    def public_evidence(self, manifest_raw: bytes | None = None) -> dict:
        evidence = copy.deepcopy(development_evidence()["corpus"]["public_adversarial"])
        raw = manifest_raw
        if raw is None:
            raw = (self.public_corpus_root() / "manifest.json").read_bytes()
        evidence["manifest"] = {
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        return evidence

    def write_public_source_tar(
        self,
        archive_path: Path,
        *,
        overrides: dict[str, bytes] | None = None,
        omitted: set[str] | None = None,
        extra: list[tuple[tarfile.TarInfo, bytes | None]] | None = None,
    ) -> None:
        source = self.public_corpus_root()
        prefix = "cyber-abuse-guard-v0.16-rc.4"
        corpus_prefix = prefix + "/testdata/round9-public-adversarial-v13"
        overrides = overrides or {}
        omitted = omitted or set()
        entries: list[tuple[tarfile.TarInfo, bytes | None]] = []

        for name in (prefix, prefix + "/testdata", corpus_prefix, corpus_prefix + "/payloads"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            entries.append((info, None))
        for path in sorted(source.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(source).as_posix()
            if relative in omitted:
                continue
            raw = overrides.get(relative, path.read_bytes())
            info = tarfile.TarInfo(corpus_prefix + "/" + relative)
            info.size = len(raw)
            info.mode = 0o644
            entries.append((info, raw))
        entries.extend(extra or [])

        with tarfile.open(archive_path, mode="w:gz") as archive:
            for info, raw in entries:
                archive.addfile(info, None if raw is None else io.BytesIO(raw))

    @staticmethod
    def phase1_zip_bytes(
        *,
        duplicate_name: str | None = None,
        symlink_name: str | None = None,
        traversal: bool = False,
    ) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(ARTIFACT_NAMES):
                if name == symlink_name:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(info, b"target")
                else:
                    archive.writestr(name, (name + "\n").encode("ascii"))
            if duplicate_name is not None:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr(duplicate_name, b"duplicate\n")
            if traversal:
                archive.writestr("../escape", b"escape\n")
        return output.getvalue()

    @staticmethod
    def patch_zip_central_file_size(raw: bytes, name: str, size: int) -> bytes:
        """Change one central-directory size without allocating the claimed bytes."""

        value = bytearray(raw)
        end = value.rfind(b"PK\x05\x06")
        if end < 0:
            raise AssertionError("test ZIP lacks an end-of-central-directory record")
        position = int.from_bytes(value[end + 16 : end + 20], "little")
        while value[position : position + 4] == b"PK\x01\x02":
            name_length = int.from_bytes(value[position + 28 : position + 30], "little")
            extra_length = int.from_bytes(value[position + 30 : position + 32], "little")
            comment_length = int.from_bytes(value[position + 32 : position + 34], "little")
            member_name = bytes(value[position + 46 : position + 46 + name_length]).decode(
                "ascii"
            )
            if member_name == name:
                value[position + 24 : position + 28] = size.to_bytes(4, "little")
                return bytes(value)
            position += 46 + name_length + extra_length + comment_length
        raise AssertionError(f"test ZIP central directory lacks {name}")

    @staticmethod
    def write_corpus_tar(
        archive_path: Path,
        *,
        duplicate: bool = False,
        link_type: bytes | None = None,
        traversal: bool = False,
    ) -> None:
        names = sorted(CORPUS_ARCHIVE_NAMES)
        replacement = names[0]
        with tarfile.open(archive_path, mode="w") as archive:
            for name in names:
                info = tarfile.TarInfo(name)
                if name == replacement and link_type is not None:
                    info.type = link_type
                    info.linkname = names[1]
                    archive.addfile(info)
                else:
                    raw = (name + "\n").encode("ascii")
                    info.size = len(raw)
                    archive.addfile(info, io.BytesIO(raw))
            if duplicate:
                raw = b"duplicate\n"
                info = tarfile.TarInfo(replacement)
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
            if traversal:
                raw = b"escape\n"
                info = tarfile.TarInfo("../escape")
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))

    def test_public_source_tar_extraction_is_manifest_bound_and_fail_closed(self) -> None:
        manifest_raw = (self.public_corpus_root() / "manifest.json").read_bytes()
        evidence = self.public_evidence(manifest_raw)
        expected_identity = {
            "schema": "round9-public-adversarial-corpus/v13",
            "dataset": "round9-public-adversarial-v13",
            "bytes": 481_448,
            "sha256": "91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "valid.tar.gz"
            self.write_public_source_tar(valid)
            output = root / "valid-output"
            self.assertEqual(
                safe_extract_public_development_corpus(valid, output, evidence),
                expected_identity,
            )
            self.assertEqual(
                {path.relative_to(output).as_posix() for path in output.rglob("*")},
                {
                    "manifest.json",
                    "payloads",
                    *{
                        "payloads/" + path.name
                        for path in (self.public_corpus_root() / "payloads").iterdir()
                    },
                },
            )

            def reject(
                name: str,
                pattern: str,
                *,
                overrides: dict[str, bytes] | None = None,
                omitted: set[str] | None = None,
                extra: list[tuple[tarfile.TarInfo, bytes | None]] | None = None,
                changed_evidence: dict | None = None,
            ) -> None:
                archive = root / f"{name}.tar.gz"
                self.write_public_source_tar(
                    archive,
                    overrides=overrides,
                    omitted=omitted,
                    extra=extra,
                )
                with self.assertRaisesRegex(ContractError, pattern):
                    safe_extract_public_development_corpus(
                        archive,
                        root / f"{name}-output",
                        changed_evidence or evidence,
                    )

            traversal = tarfile.TarInfo(
                "cyber-abuse-guard-v0.16-rc.4/testdata/../../escape"
            )
            traversal.size = 1
            reject("traversal", "invalid path|outside its fixed prefix", extra=[(traversal, b"x")])

            for kind, link_type in (("symlink", tarfile.SYMTYPE), ("hardlink", tarfile.LNKTYPE)):
                link = tarfile.TarInfo(f"cyber-abuse-guard-v0.16-rc.4/{kind}")
                link.type = link_type
                link.linkname = "cyber-abuse-guard-v0.16-rc.4/testdata"
                reject(kind, "link or special file", extra=[(link, None)])

            duplicate = tarfile.TarInfo(
                "cyber-abuse-guard-v0.16-rc.4/testdata/round9-public-adversarial-v13/manifest.json"
            )
            duplicate.size = len(manifest_raw)
            reject(
                "duplicate",
                "duplicate normalized paths",
                extra=[(duplicate, manifest_raw)],
            )

            extra_corpus = tarfile.TarInfo(
                "cyber-abuse-guard-v0.16-rc.4/testdata/round9-public-adversarial-v13/extra.txt"
            )
            extra_corpus.size = 1
            reject(
                "extra-corpus",
                "extra or missing entry",
                extra=[(extra_corpus, b"x")],
            )
            reject(
                "missing-corpus",
                "extra or missing entry",
                omitted={"README.md"},
            )

            drifted_manifest = manifest_raw.replace(b'"queried_at"', b'"queried_ax"', 1)
            self.assertEqual(len(drifted_manifest), len(manifest_raw))
            reject(
                "manifest-drift",
                "manifest digest differs",
                overrides={"manifest.json": drifted_manifest},
            )

            payload_name = next(
                path.name for path in sorted((self.public_corpus_root() / "payloads").iterdir())
            )
            payload_raw = (self.public_corpus_root() / "payloads" / payload_name).read_bytes()
            replacement = (b"A" if payload_raw[:1] != b"A" else b"B") + payload_raw[1:]
            reject(
                "payload-drift",
                "payload|base64",
                overrides={"payloads/" + payload_name: replacement},
            )

            unsafe_manifest = json.loads(manifest_raw)
            unsafe_manifest["payloads"][0]["encoded_file"] = "payloads/../escape.b64"
            unsafe_raw = canonical_bytes(unsafe_manifest)
            reject(
                "unsafe-encoded-path",
                "encoded path is invalid",
                overrides={"manifest.json": unsafe_raw},
                changed_evidence=self.public_evidence(unsafe_raw),
            )

    def test_phase1_zip_rejects_duplicate_link_traversal_and_oversize(self) -> None:
        target = sorted(ARTIFACT_NAMES)[0]
        valid = self.phase1_zip_bytes()
        oversized = self.patch_zip_central_file_size(valid, target, 536_870_913)
        cases = {
            "duplicate": (
                self.phase1_zip_bytes(duplicate_name=target),
                "exact 17 assets",
            ),
            "symlink": (
                self.phase1_zip_bytes(symlink_name=target),
                "unsafe entry",
            ),
            "traversal": (
                self.phase1_zip_bytes(traversal=True),
                "exact 17 assets",
            ),
            "oversize": (oversized, "unsafe entry|reviewed bound"),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "valid-output"
            output.mkdir()
            safe_extract_zip(valid, output)
            self.assertEqual({path.name for path in output.iterdir()}, ARTIFACT_NAMES)

        for name, (raw, pattern) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = root / "output"
                output.mkdir()
                with self.assertRaisesRegex(ContractError, pattern):
                    safe_extract_zip(raw, output)
                self.assertFalse((root / "escape").exists())

    def test_decrypted_corpus_tar_rejects_duplicate_links_traversal_and_oversize(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "valid.tar"
            self.write_corpus_tar(archive)
            output = root / "valid-output"
            safe_extract_corpus(archive, output)
            self.assertEqual({path.name for path in output.iterdir()}, CORPUS_ARCHIVE_NAMES)

        cases = {
            "duplicate": {"duplicate": True},
            "symlink": {"link_type": tarfile.SYMTYPE},
            "hardlink": {"link_type": tarfile.LNKTYPE},
            "traversal": {"traversal": True},
        }
        for name, options in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / f"{name}.tar"
                self.write_corpus_tar(archive, **options)
                with self.assertRaisesRegex(ContractError, "entries are not exact|unsafe entry"):
                    safe_extract_corpus(archive, root / "output")
                self.assertFalse((root / "escape").exists())

        members: list[tarfile.TarInfo] = []
        for index, name in enumerate(sorted(CORPUS_ARCHIVE_NAMES)):
            info = tarfile.TarInfo(name)
            info.size = 268_435_457 if index == 0 else 1
            members.append(info)
        fake_archive = mock.MagicMock()
        fake_archive.__enter__.return_value = fake_archive
        fake_archive.getmembers.return_value = members
        with tempfile.TemporaryDirectory() as directory, mock.patch(
            "cag_round9_eval_broker.tarfile.open", return_value=fake_archive
        ):
            root = Path(directory)
            with self.assertRaisesRegex(ContractError, "unsafe entry|reviewed bound"):
                safe_extract_corpus(root / "oversize.tar", root / "output")
        fake_archive.extractfile.assert_not_called()

    def test_dispatch_identity_is_bound_to_exact_tag_and_workflow_source(self) -> None:
        validate_dispatch(self.args, self.args.repository)
        for name, value in (
            ("dispatch_ref", "refs/heads/main"),
            ("dispatch_sha", "f" * 40),
            ("workflow_ref", f"{self.args.repository}/{HOST_WORKFLOW}@refs/heads/main"),
            ("workflow_sha", "e" * 40),
        ):
            with self.subTest(name=name):
                changed = copy.copy(self.args)
                setattr(changed, name, value)
                with self.assertRaises(ContractError):
                    validate_dispatch(changed, self.args.repository)

    def build_metadata(self) -> dict:
        return {
            "schema_version": 4,
            "version": "0.16-rc.4",
            "source_version": "0.16",
            "commit": self.args.commit,
            "tree": self.args.tree,
            "ruleset_version": self.args.ruleset_version,
            "ruleset_sha256": self.args.ruleset_sha256,
            "classifier_policy_version": self.args.classifier_policy_version,
            "classifier_policy_sha256": self.args.classifier_policy_sha256,
            "streaming_scanner": "streaming-scanner-v1",
            "dirty": False,
            "source_date_epoch": 1,
            "go_version": "go1.26.4",
            "goos": "linux",
            "goarch": "amd64",
            "cgo_enabled": True,
            "cc_command": "gcc",
            "gcc_version": "gcc 15",
            "gcc_target": "x86_64-linux-gnu",
            "binutils_ld_version": "GNU ld",
            "glibc_version": "glibc 2.43",
            "builder_image": "docker.io/example/builder",
            "builder_image_digest": "sha256:" + "c" * 64,
            "builder_reference": "docker.io/example/builder@sha256:" + "c" * 64,
            "runner_label": "ubuntu-26.04",
            "runner_os": "Linux",
            "runner_arch": "X64",
            "runner_environment": "github-hosted",
            "runner_name": "UNRECORDED",
            "runner_image_os": "UNRECORDED",
            "runner_image_version": "UNRECORDED",
        }

    def ruleset_manifest(self) -> dict:
        return {
            "schema_version": 1,
            "plugin_version": "0.16-rc.4",
            "ruleset_version": self.args.ruleset_version,
            "ruleset_sha256": self.args.ruleset_sha256,
            "files": [
                {"path": path, "sha256": f"{index + 1:x}" * 64}
                for index, path in enumerate(sorted(RULESET_PATHS))
            ],
        }

    def release_manifest(self) -> dict:
        development = development_evidence(
            tag_object_sha=self.args.tag_object_sha,
            commit=self.args.commit,
            tree=self.args.tree,
            classifier_version=self.args.classifier_policy_version,
            classifier_sha256=self.args.classifier_policy_sha256,
            ruleset_version=self.args.ruleset_version,
            ruleset_sha256=self.args.ruleset_sha256,
        )
        not_provided = {
            "state": "NOT_PROVIDED",
            "reason": "EXTERNAL_EVALUATION_REQUIRED",
        }
        round9_corpus = dict(development["corpus"])
        round9_corpus.update(
            {
                "independent_benign": not_provided,
                "independent_malicious": not_provided,
            }
        )
        return {
            "schema_version": 6,
            "release_phase": "candidate",
            "publish_rc_release": False,
            "status": "ROUND9_INTERNAL_GATES_PASS",
            "packaging_profile": "ROUND9_SCHEMA6",
            "source_version": "0.16",
            "artifact_version": "0.16-rc.4",
            "tag": self.args.tag,
            "tag_object": self.args.tag_object_sha,
            "commit": self.args.commit,
            "tree": self.args.tree,
            "source_date_epoch": 1,
            "ci_run_id": self.args.phase1_run_id,
            "ci_run_attempt": self.args.phase1_run_attempt,
            "artifact_count": len(ARTIFACT_NAMES),
            "cpa": {
                "primary": {
                    "version": "v7.2.95",
                    "commit": "f71ec0eb6776854457892452cf28c47f0d658251",
                    "source_compatibility": "PASS",
                    "counted_mock_validation": "NOT_RUN / EXTERNAL_EVALUATION_REQUIRED",
                },
                "external_evaluation_validation": "NOT_RUN / EXTERNAL_EVALUATION_REQUIRED",
                "external_evaluation_origin": "NOT_PROVIDED / EXTERNAL_EVALUATION_REQUIRED",
                "external_evaluation_claim": "NOT_RUN / EXTERNAL_EVALUATION_REQUIRED",
                "real_provider_validation": "NOT_RUN / PROHIBITED",
            },
            "production_validation": "NOT_RUN / PROHIBITED",
            "independent_audit": "NOT_PROVIDED",
            "independent_audit_requirement": "required",
            "independent_evaluation": "NOT_PROVIDED",
            "independent_evaluation_requirement": "required",
            "workflow": {
                "repository": self.args.repository,
                "ref": "refs/tags/v0.16-rc.4",
                "sha": self.args.commit,
                "dispatch_ref": self.args.tag,
                "run_id": self.args.phase1_run_id,
                "run_attempt": self.args.phase1_run_attempt,
            },
            "artifacts": {
                "so": {"name": "cyber-abuse-guard-v0.16-rc.4.so", "sha256": self.args.so_sha256, "sidecar_sha256": "d" * 64},
                "store_zip": {},
                "audit_bundle": {},
                "build_metadata_sha256": self.args.build_metadata_sha256,
                "checksums_sha256": "e" * 64,
                "ruleset_manifest_sha256": self.args.ruleset_manifest_sha256,
                "ruleset_sha256": "f" * 64,
                "sbom_sha256": "1" * 64,
                "test_summary": {},
                "rc_evidence": {},
                "source_archive": {},
            },
            "round9": {
                "release_lane": "round9",
                "classifier": {"version": self.args.classifier_policy_version, "sha256": self.args.classifier_policy_sha256},
                "ruleset": {"version": self.args.ruleset_version, "sha256": self.args.ruleset_sha256},
                "corpus_contract_status": "PASS",
                "corpus": round9_corpus,
                "audit_contract": development["audit_contract"],
                "machine_reports": development["machine_reports"],
                "development_evidence": development,
                "counted_mock": not_provided,
                "external_evaluation": not_provided,
                "external_ledger_proof": not_provided,
                "release": {
                    "tag": self.args.tag,
                    "title": "independent audit required",
                    "body": "NOT_PROVIDED / HOST_TEST_REQUIRED",
                    "publication_permitted": False,
                    "draft": False,
                    "prerelease": True,
                    "latest": False,
                    "asset_allowlist": sorted(ARTIFACT_NAMES),
                },
                "cpa_contract": {
                    "version": "v7.2.95",
                    "commit": "f71ec0eb6776854457892452cf28c47f0d658251",
                    "upstream_version_policy": "fixed-no-automatic-follow",
                },
            },
        }

    def test_phase1_manifests_bind_full_candidate_identity(self) -> None:
        validate_phase1_build_metadata(self.build_metadata(), self.args)
        validate_phase1_ruleset_manifest(self.ruleset_manifest(), self.args)
        validate_phase1_release_manifest(
            self.release_manifest(),
            self.args,
            so_sha256=self.args.so_sha256,
            build_metadata_sha256=self.args.build_metadata_sha256,
            ruleset_manifest_sha256=self.args.ruleset_manifest_sha256,
        )
        candidate = candidate_identity(
            self.args,
            {
                "so_sha256": self.args.so_sha256,
                "classifier_policy_version": self.args.classifier_policy_version,
                "classifier_policy_sha256": self.args.classifier_policy_sha256,
                "ruleset_version": self.args.ruleset_version,
                "ruleset_sha256": self.args.ruleset_sha256,
                "ruleset_manifest_sha256": self.args.ruleset_manifest_sha256,
                "build_metadata_sha256": self.args.build_metadata_sha256,
                "release_manifest_sha256": self.args.release_manifest_sha256,
            },
        )
        self.assertEqual(candidate["source_version"], "0.16")
        self.assertEqual(candidate["cpa_version"], "v7.2.95")
        self.assertEqual(candidate["classifier_policy_sha256"], self.args.classifier_policy_sha256)

    def test_phase1_manifest_requires_schema6_and_closed_external_placeholders(self) -> None:
        def validate(value: dict) -> None:
            validate_phase1_release_manifest(
                value,
                self.args,
                so_sha256=self.args.so_sha256,
                build_metadata_sha256=self.args.build_metadata_sha256,
                ruleset_manifest_sha256=self.args.ruleset_manifest_sha256,
            )

        changed = self.release_manifest()
        changed["schema_version"] = 5
        with self.assertRaisesRegex(ContractError, "schema_version"):
            validate(changed)

        changed = self.release_manifest()
        changed["round9"].pop("development_evidence")
        with self.assertRaisesRegex(ContractError, "keys are not exact"):
            validate(changed)

        changed = self.release_manifest()
        changed["round9"]["development_evidence"]["candidate"]["commit"] = "0" * 40
        with self.assertRaisesRegex(ContractError, "candidate identity"):
            validate(changed)

        changed = self.release_manifest()
        changed["round9"]["counted_mock"] = {
            "schema": "round9-external-counted-mock/v1",
            "state": "PASS",
        }
        with self.assertRaisesRegex(ContractError, "evidence boundary"):
            validate(changed)

    def test_candidate_identity_input_is_canonical_bounded_and_exact(self) -> None:
        identity = {
            "so_sha256": self.args.so_sha256,
            "classifier_policy_version": self.args.classifier_policy_version,
            "classifier_policy_sha256": self.args.classifier_policy_sha256,
            "ruleset_version": self.args.ruleset_version,
            "ruleset_sha256": self.args.ruleset_sha256,
            "ruleset_manifest_sha256": self.args.ruleset_manifest_sha256,
            "build_metadata_sha256": self.args.build_metadata_sha256,
            "release_manifest_sha256": self.args.release_manifest_sha256,
        }
        raw = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        args = argparse.Namespace(candidate_identity=raw)
        self.assertEqual(apply_candidate_identity_input(args), identity)
        for key, value in identity.items():
            self.assertEqual(getattr(args, key), value)

        with self.assertRaisesRegex(ContractError, "canonical.*JSON"):
            apply_candidate_identity_input(
                argparse.Namespace(candidate_identity=json.dumps(identity))
            )
        with self.assertRaisesRegex(ContractError, "duplicate"):
            apply_candidate_identity_input(
                argparse.Namespace(
                    candidate_identity='{"so_sha256":"' + "1" * 64 + '","so_sha256":"' + "2" * 64 + '"}'
                )
            )
        changed = dict(identity)
        changed["unexpected"] = "value"
        with self.assertRaisesRegex(ContractError, "keys|fields"):
            apply_candidate_identity_input(
                argparse.Namespace(
                    candidate_identity=json.dumps(
                        changed, sort_keys=True, separators=(",", ":")
                    )
                )
            )

    def test_phase1_policy_tamper_is_rejected(self) -> None:
        metadata = self.build_metadata()
        metadata["classifier_policy_sha256"] = "0" * 64
        with self.assertRaisesRegex(ContractError, "classifier_policy_sha256"):
            validate_phase1_build_metadata(metadata, self.args)

    def test_evaluator_and_execution_include_every_pinned_component(self) -> None:
        config = {
            "identities": {
                "evaluator_version": "cag-round9-external-evaluator-v3",
                "evaluator_sha256": "1" * 64,
                "core_sha256": "2" * 64,
                "broker_sha256": "3" * 64,
                "evaluator_key_id": "round9-evaluator-key-v1",
                "sandbox_adapter_sha256": "4" * 64,
                "sandbox_adapter_config_sha256": "5" * 64,
                "docker_sandbox_sha256": "6" * 64,
            },
            "sandbox": {
                "sandbox_id": "round9-sandbox-v1",
                "daemon_id": "round9-daemon-v1",
                "probe_image_id": "sha256:" + "7" * 64,
                "cpa_image_id": "sha256:" + "8" * 64,
                "counted_mock_image_id": "sha256:" + "9" * 64,
                "model": "gpt-5.4",
                "scan_limit_bytes": 16384,
            },
        }
        evaluator = evaluator_identity(config)
        execution = execution_identity(config, self.args)
        self.assertEqual(evaluator["core_sha256"], "2" * 64)
        self.assertEqual(evaluator["broker_sha256"], "3" * 64)
        self.assertEqual(execution["sandbox_adapter_config_sha256"], "5" * 64)
        self.assertEqual(execution["counted_mock_image_id"], "sha256:" + "9" * 64)
        self.assertEqual(execution["model"], "gpt-5.4")
        self.assertEqual(execution["network_binding"], FIXED_NETWORK_BINDING)
        self.assertEqual(execution["phase_protocol"], FIXED_PHASE_PROTOCOL)

    def test_openssl_canonicalizes_private_and_public_ed25519_keys_to_der_spki(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "evaluator-private.pem"
            public_key = root / "evaluator-public.pem"
            private_key.write_text("private test fixture\n", encoding="utf-8")
            public_key.write_text("public test fixture\n", encoding="utf-8")
            spki = bytes.fromhex("302a300506032b6570032100") + b"e" * 32
            calls: list[list[str]] = []

            def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
                calls.append(command)
                self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
                self.assertEqual(kwargs["env"], minimal_subprocess_env())
                self.assertEqual(kwargs["timeout"], 30)
                return SimpleNamespace(returncode=0, stdout=spki, stderr=b"")

            with mock.patch("cag_round9_eval_broker.subprocess.run", side_effect=fake_run):
                self.assertEqual(
                    canonical_ed25519_public_spki(
                        private_key, private_key=True, openssl="/usr/bin/openssl"
                    ),
                    spki,
                )
                self.assertEqual(
                    canonical_ed25519_public_spki(
                        public_key, private_key=False, openssl="/usr/bin/openssl"
                    ),
                    spki,
                )
            self.assertEqual(
                calls,
                [
                    [
                        "/usr/bin/openssl",
                        "pkey",
                        "-in",
                        str(private_key),
                        "-pubout",
                        "-outform",
                        "DER",
                    ],
                    [
                        "/usr/bin/openssl",
                        "pkey",
                        "-pubin",
                        "-in",
                        str(public_key),
                        "-pubout",
                        "-outform",
                        "DER",
                    ],
                ],
            )

            with mock.patch(
                "cag_round9_eval_broker.subprocess.run",
                return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b"rejected"),
            ):
                with self.assertRaisesRegex(ContractError, "failed to canonicalize"):
                    canonical_ed25519_public_spki(
                        public_key, private_key=False, openssl="/usr/bin/openssl"
                    )
            with mock.patch(
                "cag_round9_eval_broker.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=0, stdout=b"not-ed25519-spki", stderr=b""
                ),
            ):
                with self.assertRaisesRegex(ContractError, "not canonical Ed25519"):
                    canonical_ed25519_public_spki(
                        public_key, private_key=False, openssl="/usr/bin/openssl"
                    )

    def test_signing_key_material_requires_matching_evaluator_pair_and_distinct_author(self) -> None:
        evaluator_private = Path("/root/evaluator-private.pem")
        evaluator_public = Path("/root/evaluator-public.pem")
        author_public = Path("/root/author-public.pem")
        evaluator_spki = bytes.fromhex("302a300506032b6570032100") + b"e" * 32
        author_spki = bytes.fromhex("302a300506032b6570032100") + b"a" * 32

        with mock.patch(
            "cag_round9_eval_broker.canonical_ed25519_public_spki",
            side_effect=[evaluator_spki, evaluator_spki, author_spki],
        ):
            validate_signing_key_material(
                evaluator_private,
                evaluator_public,
                author_public,
                openssl="/usr/bin/openssl",
            )

        with mock.patch(
            "cag_round9_eval_broker.canonical_ed25519_public_spki",
            side_effect=[evaluator_spki, author_spki],
        ):
            with self.assertRaisesRegex(ContractError, "private/public.*do not match"):
                validate_signing_key_material(
                    evaluator_private,
                    evaluator_public,
                    author_public,
                    openssl="/usr/bin/openssl",
                )

        # Key IDs are intentionally absent here: differently encoded PEM files or
        # different IDs cannot make identical canonical key material distinct.
        with mock.patch(
            "cag_round9_eval_broker.canonical_ed25519_public_spki",
            side_effect=[evaluator_spki, evaluator_spki, evaluator_spki],
        ):
            with self.assertRaisesRegex(ContractError, "key material must be distinct"):
                validate_signing_key_material(
                    evaluator_private,
                    evaluator_public,
                    author_public,
                    openssl="/usr/bin/openssl",
                )

    def test_github_redirect_and_artifact_download_never_forward_pat(self) -> None:
        client = GitHubClient("https://api.github.com", "root-secret-pat")
        first_hop: list[object] = []
        second_hop: list[object] = []
        redirect_headers = Message()
        redirect_headers["Location"] = "https://storage.example.invalid/artifact.zip?sig=opaque"

        class APIOpener:
            def open(self, operation, **_kwargs):  # noqa: ANN001
                first_hop.append(operation)
                return FakeHTTPResponse(302, headers=redirect_headers)

        class ArtifactOpener:
            def open(self, operation, **_kwargs):  # noqa: ANN001
                second_hop.append(operation)
                return FakeHTTPResponse(200, b"artifact-bytes")

        client._api_opener = APIOpener()  # type: ignore[assignment]
        client._artifact_opener = ArtifactOpener()  # type: ignore[assignment]
        self.assertEqual(client.bytes("repos/example/project/actions/artifacts/1/zip"), b"artifact-bytes")
        self.assertEqual(len(first_hop), 1)
        self.assertEqual(first_hop[0].get_header("Authorization"), "Bearer root-secret-pat")
        self.assertEqual(len(second_hop), 1)
        self.assertIsNone(second_hop[0].get_header("Authorization"))
        self.assertEqual(
            second_hop[0].full_url,
            "https://storage.example.invalid/artifact.zip?sig=opaque",
        )

        client._api_opener = APIOpener()  # type: ignore[assignment]
        with self.assertRaisesRegex(ContractError, "redirect was rejected"):
            client.json("GET", "repos/example/project")
        self.assertEqual(len(first_hop), 2)

    def test_artifact_redirect_location_is_strict_uncredentialed_https(self) -> None:
        bad_locations = (
            "http://storage.example.invalid/artifact.zip",
            "https://user:password@storage.example.invalid/artifact.zip",  # repo-secret-scan: allow synthetic-fixture
            "https://storage.example.invalid:444/artifact.zip",
            "https://storage.example.invalid/artifact.zip#fragment",
            "//storage.example.invalid/artifact.zip",
            "https:///missing-host",
            "https://storage.example.invalid/artifact.zip\r\nX-Evil: yes",
            "https://storage.example.invalid/artifact zip",
            "https://storage.example.invalid/artifact\tzip",
            "https:\\storage.example.invalid\\artifact.zip",
        )
        for location in bad_locations:
            with self.subTest(location=location):
                client = GitHubClient("https://api.github.com", "root-secret-pat")
                headers = Message()
                try:
                    headers["Location"] = location
                except ValueError:
                    headers = {"Location": location}  # type: ignore[assignment]

                class APIOpener:
                    def open(self, _operation, **_kwargs):  # noqa: ANN001
                        return FakeHTTPResponse(302, headers=headers)  # type: ignore[arg-type]

                client._api_opener = APIOpener()  # type: ignore[assignment]
                with self.assertRaisesRegex(ContractError, "Location|uncredentialed HTTPS"):
                    client.bytes("repos/example/project/actions/artifacts/1/zip")

    def test_recover_abort_accepts_the_same_completed_failed_host_run_only(self) -> None:
        test_args = self.args

        class Client:
            def __init__(self, status: str, conclusion: str | None):
                self.status = status
                self.conclusion = conclusion

            def ref(self, _repository: str, full_ref: str, *, absent_ok: bool = False):
                del absent_ok
                if full_ref == "refs/heads/main":
                    return {"object": {"type": "commit", "sha": test_args.commit}}
                if full_ref == f"refs/tags/{test_args.tag}":
                    return {"object": {"type": "tag", "sha": test_args.tag_object_sha}}
                raise AssertionError(full_ref)

            def tag(self, _repository: str, _tag_sha: str):
                return {"object": {"type": "commit", "sha": test_args.commit}}

            def json(self, _method: str, endpoint: str, _payload=None):  # noqa: ANN001
                prefix = f"repos/{test_args.repository}/"
                if endpoint == prefix + f"git/commits/{test_args.commit}":
                    return {"tree": {"sha": test_args.tree}}
                if endpoint == prefix + f"actions/runs/{test_args.workflow_run_id}":
                    return {
                        "id": test_args.workflow_run_id,
                        "run_attempt": test_args.workflow_run_attempt,
                        "name": HOST_WORKFLOW_NAME,
                        "path": HOST_WORKFLOW,
                        "event": "workflow_dispatch",
                        "head_sha": test_args.commit,
                        "status": self.status,
                        "conclusion": self.conclusion,
                        "repository": {"full_name": test_args.repository},
                    }
                if endpoint == prefix + f"actions/runs/{test_args.phase1_run_id}":
                    return {
                        "id": test_args.phase1_run_id,
                        "run_attempt": test_args.phase1_run_attempt,
                        "name": PHASE1_WORKFLOW_NAME,
                        "path": RELEASE_WORKFLOW,
                        "event": "workflow_dispatch",
                        "head_sha": test_args.commit,
                        "status": "completed",
                        "conclusion": "success",
                        "repository": {"full_name": test_args.repository},
                    }
                if endpoint == prefix + f"actions/artifacts/{test_args.phase1_artifact_id}":
                    return {
                        "id": test_args.phase1_artifact_id,
                        "name": f"round9-rc-{test_args.tag}-{test_args.commit}-{test_args.phase1_run_id}-{test_args.phase1_run_attempt}",
                        "digest": test_args.phase1_artifact_digest,
                        "expired": False,
                        "workflow_run": {"id": test_args.phase1_run_id},
                    }
                raise AssertionError(endpoint)

        failed = Client("completed", "failure")
        with self.assertRaisesRegex(ContractError, "Host workflow"):
            verify_remote_identity(failed, self.args)
        verify_remote_identity(Client("in_progress", None), self.args)
        verify_remote_identity(failed, self.args, require_failed_host_run=True)
        for status, conclusion in (
            ("completed", "success"),
            ("completed", "neutral"),
            ("completed", "skipped"),
            ("in_progress", None),
            ("in_progress", "failure"),
        ):
            with self.subTest(status=status, conclusion=conclusion):
                with self.assertRaisesRegex(ContractError, "Host workflow"):
                    verify_remote_identity(
                        Client(status, conclusion),
                        self.args,
                        require_failed_host_run=True,
                    )

    def test_create_ref_lost_response_recovers_only_exact_annotated_tag(self) -> None:
        client = GitHubClient("https://api.github.com", "root-secret-pat")
        full_ref = "refs/tags/round9-eval-ledger/" + "a" * 64 + "/reserved"
        tag_sha = "b" * 40
        with (
            mock.patch.object(
                client,
                "json",
                side_effect=[{"sha": tag_sha}, ContractError("lost create-ref response")],
            ),
            mock.patch.object(
                client,
                "ref",
                return_value={"object": {"type": "tag", "sha": tag_sha}},
            ),
        ):
            self.assertEqual(
                client.create_tagged_ref(
                    self.args.repository, full_ref, self.args.commit, "signed-message"
                ),
                tag_sha,
            )

        for recovered in (
            None,
            {"object": {"type": "commit", "sha": tag_sha}},
            {"object": {"type": "tag", "sha": "c" * 40}},
        ):
            with self.subTest(recovered=recovered):
                client = GitHubClient("https://api.github.com", "root-secret-pat")
                with (
                    mock.patch.object(
                        client,
                        "json",
                        side_effect=[
                            {"sha": tag_sha},
                            ContractError("lost create-ref response"),
                        ],
                    ),
                    mock.patch.object(client, "ref", return_value=recovered),
                ):
                    with self.assertRaises(ContractError):
                        client.create_tagged_ref(
                            self.args.repository,
                            full_ref,
                            self.args.commit,
                            "signed-message",
                        )

    def test_ledger_ruleset_requires_empty_bypass_and_exclude_lists(self) -> None:
        ruleset = {
            "id": 19602252,
            "name": "round9-eval-ledger-immutable",
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": ["refs/tags/round9-eval-ledger/**"],
                    "exclude": [],
                }
            },
            "rules": [{"type": "deletion"}, {"type": "update"}],
        }
        config = {
            "repository": self.args.repository,
            "github": {
                "ledger_ruleset_id": 19602252,
                "ledger_ruleset_name": "round9-eval-ledger-immutable",
            },
        }

        class Client:
            def __init__(self, value: dict):
                self.value = value

            def json(self, *_args: object, **_kwargs: object) -> dict:
                return self.value

        verify_ledger_ruleset(Client(copy.deepcopy(ruleset)), config)
        for path, value in (
            (("bypass_actors",), None),
            (("bypass_actors",), [{"actor_id": 1}]),
            (("conditions", "ref_name", "exclude"), None),
            (("conditions", "ref_name", "exclude"), ["refs/tags/round9-eval-ledger/unsafe"]),
        ):
            with self.subTest(path=path, value=value):
                changed = copy.deepcopy(ruleset)
                target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ContractError):
                    verify_ledger_ruleset(Client(changed), config)

        invalid_rules = (
            ("missing", None),
            ("not-list", {}),
            ("non-object-entry", ["deletion", {"type": "update"}]),
            ("missing-type", [{}, {"type": "update"}]),
            ("non-string-type", [{"type": "deletion"}, {"type": None}]),
            (
                "non-fast-forward-is-not-update",
                [{"type": "deletion"}, {"type": "non_fast_forward"}],
            ),
            (
                "update-without-deletion",
                [{"type": "update"}, {"type": "non_fast_forward"}],
            ),
            ("deletion-only", [{"type": "deletion"}]),
            ("update-only", [{"type": "update"}]),
        )
        for label, value in invalid_rules:
            with self.subTest(rules=label):
                changed = copy.deepcopy(ruleset)
                changed["rules"] = value
                with self.assertRaisesRegex(ContractError, "ruleset"):
                    verify_ledger_ruleset(Client(changed), config)

    def test_ruleset_drift_before_result_and_after_proof_fails_closed(self) -> None:
        for failure_call, expected_events in (
            (3, ["reserved", "started"]),
            (4, ["reserved", "started", "result"]),
        ):
            with self.subTest(failure_call=failure_call), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                work_root = root / "work"
                state_root = root / "state"
                work_root.mkdir()
                state_root.mkdir()
                token = root / "token"
                token.write_text("token\n", encoding="ascii")
                candidate_so = root / "candidate.so"
                candidate_so.write_bytes(b"candidate")
                present: set[str] = set()
                events: list[str] = []

                class FakeClient:
                    def __init__(self, *_args: object, **_kwargs: object):
                        pass

                    def ref(self, _repository: str, full_ref: str, *, absent_ok: bool = False):
                        del absent_ok
                        event = full_ref.rsplit("/", 1)[-1]
                        if event in present:
                            return {"object": {"type": "tag", "sha": "f" * 40}}
                        return None

                fake_client = FakeClient()
                config = {
                    "repository": self.args.repository,
                    "github": {
                        "token_file": str(token),
                        "api_url": "https://api.github.com",
                    },
                    "signing": {
                        "private_key": str(root / "private.pem"),
                        "public_key": str(root / "public.pem"),
                    },
                    "identities": {"evaluator_key_id": "round9-evaluator-key-v1"},
                    "_work_root": work_root,
                    "_state_root": state_root,
                    "_openssl": Path("/usr/bin/openssl"),
                }
                corpus = {"bundle_sha256": "a" * 64}
                candidate = {"commit": self.args.commit}
                evaluator = {"version": "external-v1"}
                execution = {"challenge_sha256": "b" * 64}
                development = development_evidence(
                    tag_object_sha=self.args.tag_object_sha,
                    commit=self.args.commit,
                    tree=self.args.tree,
                    classifier_version=self.args.classifier_policy_version,
                    classifier_sha256=self.args.classifier_policy_sha256,
                    ruleset_version=self.args.ruleset_version,
                    ruleset_sha256=self.args.ruleset_sha256,
                )
                asset_identity = {"so_sha256": self.args.so_sha256}

                def ruleset_side_effect(*_args: object, **_kwargs: object) -> None:
                    ruleset_side_effect.calls += 1
                    if ruleset_side_effect.calls >= failure_call:
                        raise ContractError("ledger ruleset drifted")

                ruleset_side_effect.calls = 0  # type: ignore[attr-defined]

                def fake_create_event(
                    _client: object,
                    _config: dict,
                    event: str,
                    _payload: dict,
                    _commit: str,
                ) -> str:
                    events.append(event)
                    present.add(event)
                    return "e" * 40

                patchers = (
                    mock.patch("cag_round9_eval_broker.GitHubClient", return_value=fake_client),
                    mock.patch("cag_round9_eval_broker.read_secret", return_value="token"),
                    mock.patch("cag_round9_eval_broker.verify_remote_identity"),
                    mock.patch(
                        "cag_round9_eval_broker.verify_ledger_ruleset",
                        side_effect=ruleset_side_effect,
                    ),
                    mock.patch("cag_round9_eval_broker.corpus_identity", return_value=corpus),
                    mock.patch(
                        "cag_round9_eval_broker.verify_phase1_assets",
                        return_value=(candidate_so, asset_identity, development),
                    ),
                    mock.patch("cag_round9_eval_broker.candidate_identity", return_value=candidate),
                    mock.patch("cag_round9_eval_broker.validate_development_evidence"),
                    mock.patch(
                        "cag_round9_eval_broker.safe_extract_public_development_corpus",
                        return_value=public_counted_mock()["manifest"],
                    ),
                    mock.patch("cag_round9_eval_broker.evaluator_identity", return_value=evaluator),
                    mock.patch("cag_round9_eval_broker.execution_identity", return_value=execution),
                    mock.patch("cag_round9_eval_broker.abort_verified_partial_ledger", return_value=False),
                    mock.patch("cag_round9_eval_broker.create_event", side_effect=fake_create_event),
                    mock.patch(
                        "cag_round9_eval_broker.run_external_evaluator",
                        return_value={
                            "metrics": {"synthetic": True},
                            "public_counted_mock": public_counted_mock(),
                            "privacy": {"synthetic": True},
                        },
                    ),
                    mock.patch("cag_round9_eval_broker.derive_counted_mock", return_value={"synthetic": True}),
                    mock.patch("cag_round9_eval_broker.validate_counted_mock"),
                    mock.patch(
                        "cag_round9_eval_broker.validate_public_counted_mock",
                        side_effect=lambda value, **_kwargs: value,
                    ),
                    mock.patch(
                        "cag_round9_eval_broker.validate_evaluation_payload",
                        side_effect=lambda value, **_kwargs: value,
                    ),
                    mock.patch(
                        "cag_round9_eval_broker.signed_envelope",
                        return_value={"schema": "synthetic-envelope"},
                    ),
                    mock.patch("cag_round9_eval_broker.build_proof", return_value={"synthetic": True}),
                    mock.patch("cag_round9_eval_broker.validate_ledger_proof"),
                )
                with ExitStack() as stack:
                    for patcher in patchers:
                        stack.enter_context(patcher)
                    with self.assertRaisesRegex(ContractError, "ruleset drifted"):
                        evaluate_once(config, self.args)
                self.assertEqual(ruleset_side_effect.calls, 4)
                self.assertEqual(events, expected_events)

    def test_broker_child_environment_is_closed_and_proxy_free(self) -> None:
        expected = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/private/work",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
        }
        self.assertEqual(minimal_subprocess_env(home="/private/work"), expected)
        self.assertEqual(
            minimal_subprocess_env(home="/private/work", github_token="root-pat"),
            {**expected, "GH_TOKEN": "root-pat"},
        )

    def test_installer_snapshots_reviewed_inputs_before_validation_and_install(self) -> None:
        installer = (Path(__file__).resolve().parent / "install.sh").read_text(
            encoding="utf-8"
        )
        self.assertTrue(installer.startswith("#!/bin/bash\n"))
        self.assertNotIn("#!/usr/bin/env bash", installer)
        snapshot = installer.index("staging_dir=\"$(mktemp")
        validation = installer.index("# Parse both reviewed configurations")
        installation = installer.index("install -d -o root")
        self.assertLess(snapshot, validation)
        self.assertLess(validation, installation)
        for required in (
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONHOME PYTHONPATH",
            "python3 -I -B -",
            'getattr(os, "O_NOFOLLOW", 0)',
            "os.fstat(descriptor)",
            "os.fsync(output)",
            'config_source="$staging_dir/broker-config.json"',
            'adapter_config_source="$staging_dir/adapter-config.json"',
            'broker_source="$staging_dir/cag_round9_eval_broker.py"',
            'docker_sandbox_source="$staging_dir/round9_docker_sandbox.py"',
            'metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077',
        ):
            self.assertIn(required, installer)

    def test_external_evaluator_always_stops_sandbox_after_evaluator_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            encrypted = root / "independent.age"
            encrypted.write_bytes(b"encrypted")
            candidate_so = root / "candidate.so"
            candidate_so.write_bytes(b"candidate")
            work = root / "work"
            work.mkdir()
            calls: list[list[str]] = []
            environments: list[dict[str, str]] = []

            config = {
                "corpus": {
                    "encrypted_bundle": str(encrypted),
                    "age_identity": str(root / "age-identity.txt"),
                    "author_public_key": str(root / "author.pub"),
                },
                "identities": {
                    "author_key_id": "round9-author-key-v1",
                    "core_sha256": "1" * 64,
                },
                "_age": Path("/usr/bin/age"),
                "_sandbox_adapter": Path("/usr/local/libexec/cag-round9-cpa-sandbox-adapter"),
                "_sandbox_adapter_config": Path("/etc/cag-round9-eval/sandbox.json"),
                "_evaluator": Path("/usr/local/libexec/cag-round9-external-evaluator"),
            }
            args = argparse.Namespace(challenge="2" * 64)
            candidate = {"so_sha256": "3" * 64}
            corpus = {
                "bundle_sha256": "4" * 64,
                "bundle_manifest_sha256": "5" * 64,
            }
            public_root = root / "public-corpus"
            public_root.mkdir()
            public_evidence_path = root / "public-development-evidence.json"
            public_evidence_path.write_text("{}\n", encoding="utf-8")
            public_identity = public_counted_mock()["manifest"]

            def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
                calls.append([str(item) for item in command])
                environments.append(dict(kwargs["env"]))
                if command[0] == str(config["_age"]):
                    output = Path(command[command.index("--output") + 1])
                    output.write_bytes(b"decrypted tar")
                    return SimpleNamespace(returncode=0)
                if command[0] == str(config["_sandbox_adapter"]) and command[1] == "start":
                    return SimpleNamespace(returncode=0)
                if command[0] == str(config["_evaluator"]):
                    return SimpleNamespace(returncode=1)
                if command[0] == str(config["_sandbox_adapter"]) and command[1] == "stop":
                    return SimpleNamespace(returncode=0)
                raise AssertionError(f"unexpected command: {command}")

            with (
                mock.patch("cag_round9_eval_broker.subprocess.run", side_effect=fake_run),
                mock.patch("cag_round9_eval_broker.safe_extract_corpus"),
                mock.patch(
                    "cag_round9_eval_broker.sha256_file",
                    return_value=corpus["bundle_manifest_sha256"],
                ),
            ):
                with self.assertRaisesRegex(ContractError, "external evaluator failed"):
                    run_external_evaluator(
                        config,
                        args,
                        candidate_so,
                        candidate,
                        corpus,
                        {},
                        public_root,
                        public_evidence_path,
                        public_identity,
                        work,
                    )

            lifecycle = [
                command[1]
                for command in calls
                if command[0] == str(config["_sandbox_adapter"])
            ]
            self.assertEqual(lifecycle, ["start", "stop"])
            self.assertTrue(environments)
            for environment in environments:
                self.assertEqual(
                    set(environment), {"PATH", "HOME", "LANG", "LC_ALL", "TZ"}
                )
                self.assertFalse(
                    any("proxy" in key.casefold() or "token" in key.casefold() for key in environment)
                )

    def test_external_aggregate_binds_runtime_checks_to_metrics(self) -> None:
        checks = runtime_checks()
        decisions = decision_audit()
        corpus = {"identity": "synthetic-corpus"}
        execution = {
            "sandbox_id": "round9-sandbox-v1",
            "daemon_id": "round9-daemon-v1",
            "probe_image_id": "sha256:" + "1" * 64,
            "cpa_image_id": "sha256:" + "2" * 64,
            "counted_mock_image_id": "sha256:" + "3" * 64,
            "network_binding": dict(FIXED_NETWORK_BINDING),
            "phase_protocol": dict(FIXED_PHASE_PROTOCOL),
        }
        aggregate = {
            "schema": "round9-external-evaluator-aggregate/v3",
            "evaluator": {
                "version": "cag-round9-external-evaluator-v3",
                "sha256": "4" * 64,
                "core_sha256": "5" * 64,
                "execution_mode": "EXTERNAL_ROOT_OWNED_BLACK_BOX_CPA",
            },
            "corpus": corpus,
            "sandbox": {
                "candidate_so_sha256": "6" * 64,
                "cpa_version": "v7.2.95",
                "cpa_commit": "f71ec0eb6776854457892452cf28c47f0d658251",
                "cpa_image_id": execution["cpa_image_id"],
                "counted_mock_image_id": execution["counted_mock_image_id"],
                "sandbox_id": execution["sandbox_id"],
                "daemon_id": execution["daemon_id"],
                "probe_image_id": execution["probe_image_id"],
                "network_binding": execution["network_binding"],
                "phase_protocol": execution["phase_protocol"],
                "production_accessed": False,
                "real_provider_contacted": False,
                "runtime_checks": checks,
                "decision_audit": decisions,
            },
            "metrics": {
                "runtime_checks": checks,
                "decision_audit": decisions,
                "public_counted_mock": public_counted_mock(),
            },
            "public_counted_mock": public_counted_mock(),
            "privacy": {"synthetic": True},
        }
        config = {
            "identities": {
                "evaluator_version": aggregate["evaluator"]["version"],
                "evaluator_sha256": aggregate["evaluator"]["sha256"],
                "core_sha256": aggregate["evaluator"]["core_sha256"],
            }
        }
        with (
            mock.patch(
                "cag_round9_eval_broker.validate_corpus", return_value=corpus
            ),
            mock.patch(
                "cag_round9_eval_broker.validate_metrics",
                return_value={
                    "runtime_checks": checks,
                    "decision_audit": decisions,
                    "public_counted_mock": public_counted_mock(),
                },
            ),
            mock.patch("cag_round9_eval_broker.validate_runtime_checks"),
            mock.patch("cag_round9_eval_broker.validate_decision_audit"),
            mock.patch("cag_round9_eval_broker.validate_privacy"),
        ):
            validate_external_aggregate(
                aggregate, config, {"so_sha256": "6" * 64}, corpus, execution
            )
            changed = copy.deepcopy(aggregate)
            changed["sandbox"]["runtime_checks"] = {"drift": True}
            with self.assertRaisesRegex(ContractError, "runtime metrics binding"):
                validate_external_aggregate(
                    changed, config, {"so_sha256": "6" * 64}, corpus, execution
                )

    def test_verified_partial_ledger_is_permanently_aborted(self) -> None:
        repository = "example/cyber-abuse-guard"
        bundle_sha256 = "a" * 64
        namespace = "round9-eval-ledger/" + bundle_sha256
        commit = "b" * 40
        base = {
            "repository": repository,
            "namespace": namespace,
            "candidate": {"commit": commit},
            "evaluator": {"version": "external-v1"},
            "corpus": {"bundle_sha256": bundle_sha256},
            "execution": {"challenge_sha256": "c" * 64},
            "development_evidence": {"schema": "synthetic-development"},
        }
        reserved_payload = ledger_event_payload("reserved", **base)
        created: list[tuple[str, dict]] = []

        class FakeClient:
            def ref(
                self,
                _repository: str,
                full_ref: str,
                *,
                absent_ok: bool = False,
            ) -> dict | None:
                del absent_ok
                if full_ref.endswith("/reserved"):
                    return {"object": {"type": "tag", "sha": "d" * 40}}
                return None

        config = {
            "repository": repository,
            "signing": {"public_key": "/root/evaluator.pub"},
            "identities": {"evaluator_key_id": "round9-evaluator-key-v1"},
            "_openssl": Path("/usr/bin/openssl"),
        }

        def fake_create_event(
            _client: object,
            _config: dict,
            event: str,
            payload: dict,
            _commit: str,
        ) -> str:
            created.append((event, payload))
            return "e" * 40

        with (
            mock.patch(
                "cag_round9_eval_broker.load_ledger_entry",
                return_value={"envelope": {"schema": "signed"}},
            ),
            mock.patch(
                "cag_round9_eval_broker.verify_signed_envelope",
                return_value=reserved_payload,
            ) as verify,
            mock.patch("cag_round9_eval_broker.validate_ledger_event_payload"),
            mock.patch(
                "cag_round9_eval_broker.create_event", side_effect=fake_create_event
            ),
        ):
            with self.assertRaisesRegex(
                ContractError, "permanently aborted"
            ):
                abort_verified_partial_ledger(
                    FakeClient(), config, namespace, base, commit
                )

        verify.assert_called_once()
        self.assertEqual([event for event, _payload in created], ["aborted"])
        self.assertEqual(created[0][1], ledger_event_payload("aborted", **base))

        class CompletedClient:
            def ref(self, _repository: str, full_ref: str, *, absent_ok: bool = False):
                del absent_ok
                if full_ref.endswith("/result"):
                    return {"object": {"type": "tag", "sha": "f" * 40}}
                return None

        with mock.patch("cag_round9_eval_broker.create_event") as create:
            with self.assertRaisesRegex(ContractError, "cannot be aborted"):
                abort_verified_partial_ledger(
                    CompletedClient(), config, namespace, base, commit, fail_after_abort=False
                )
        create.assert_not_called()

    def test_mismatched_signed_partial_ledger_is_not_aborted_as_this_run(self) -> None:
        repository = "example/cyber-abuse-guard"
        bundle_sha256 = "a" * 64
        namespace = "round9-eval-ledger/" + bundle_sha256
        commit = "b" * 40
        base = {
            "repository": repository,
            "namespace": namespace,
            "candidate": {"commit": commit},
            "evaluator": {"version": "external-v1"},
            "corpus": {"bundle_sha256": bundle_sha256},
            "execution": {"challenge_sha256": "c" * 64},
            "development_evidence": {"schema": "synthetic-development"},
        }
        mismatched = ledger_event_payload("reserved", **base)
        mismatched["candidate"] = {"commit": "f" * 40}

        class FakeClient:
            def ref(
                self,
                _repository: str,
                full_ref: str,
                *,
                absent_ok: bool = False,
            ) -> dict | None:
                del absent_ok
                if full_ref.endswith("/reserved"):
                    return {"object": {"type": "tag", "sha": "d" * 40}}
                return None

        config = {
            "repository": repository,
            "signing": {"public_key": "/root/evaluator.pub"},
            "identities": {"evaluator_key_id": "round9-evaluator-key-v1"},
            "_openssl": Path("/usr/bin/openssl"),
        }
        with (
            mock.patch(
                "cag_round9_eval_broker.load_ledger_entry",
                return_value={"envelope": {"schema": "signed"}},
            ),
            mock.patch(
                "cag_round9_eval_broker.verify_signed_envelope",
                return_value=mismatched,
            ),
            mock.patch("cag_round9_eval_broker.validate_ledger_event_payload"),
            mock.patch("cag_round9_eval_broker.create_event") as create,
        ):
            with self.assertRaisesRegex(ContractError, "identity"):
                abort_verified_partial_ledger(
                    FakeClient(), config, namespace, base, commit
                )
        create.assert_not_called()

    def test_recover_abort_is_idempotent_only_for_exact_signed_event(self) -> None:
        repository = "example/cyber-abuse-guard"
        bundle_sha256 = "a" * 64
        namespace = "round9-eval-ledger/" + bundle_sha256
        commit = "b" * 40
        base = {
            "repository": repository,
            "namespace": namespace,
            "candidate": {"commit": commit},
            "evaluator": {"version": "external-v1"},
            "corpus": {"bundle_sha256": bundle_sha256},
            "execution": {"challenge_sha256": "c" * 64},
            "development_evidence": {"schema": "synthetic-development"},
        }

        class FakeClient:
            def ref(self, _repository: str, full_ref: str, *, absent_ok: bool = False):
                del absent_ok
                if full_ref.endswith("/aborted"):
                    return {"object": {"type": "tag", "sha": "d" * 40}}
                return None

        config = {
            "repository": repository,
            "signing": {"public_key": "/root/evaluator.pub"},
            "identities": {"evaluator_key_id": "round9-evaluator-key-v1"},
            "_openssl": Path("/usr/bin/openssl"),
        }
        aborted_payload = ledger_event_payload("aborted", **base)
        with (
            mock.patch(
                "cag_round9_eval_broker.load_ledger_entry",
                return_value={"envelope": {"schema": "signed"}},
            ),
            mock.patch(
                "cag_round9_eval_broker.verify_signed_envelope",
                return_value=aborted_payload,
            ),
            mock.patch("cag_round9_eval_broker.validate_ledger_event_payload"),
            mock.patch("cag_round9_eval_broker.create_event") as create,
        ):
            self.assertTrue(
                abort_verified_partial_ledger(
                    FakeClient(),
                    config,
                    namespace,
                    base,
                    commit,
                    fail_after_abort=False,
                )
            )
        create.assert_not_called()

        mismatched = copy.deepcopy(aborted_payload)
        mismatched["execution"] = {"challenge_sha256": "e" * 64}
        with (
            mock.patch(
                "cag_round9_eval_broker.load_ledger_entry",
                return_value={"envelope": {"schema": "signed"}},
            ),
            mock.patch(
                "cag_round9_eval_broker.verify_signed_envelope",
                return_value=mismatched,
            ),
            mock.patch("cag_round9_eval_broker.validate_ledger_event_payload"),
            mock.patch("cag_round9_eval_broker.create_event") as create,
        ):
            with self.assertRaisesRegex(ContractError, "identity"):
                abort_verified_partial_ledger(
                    FakeClient(),
                    config,
                    namespace,
                    base,
                    commit,
                    fail_after_abort=False,
                )
        create.assert_not_called()

    def test_recover_abort_subcommand_is_explicit_and_root_only(self) -> None:
        candidate_identity = {
            key: getattr(self.args, key)
            for key in (
                "so_sha256",
                "classifier_policy_version",
                "classifier_policy_sha256",
                "ruleset_version",
                "ruleset_sha256",
                "ruleset_manifest_sha256",
                "build_metadata_sha256",
                "release_manifest_sha256",
            )
        }
        argv = [
            "recover-abort",
            "--repository",
            self.args.repository,
            "--tag",
            self.args.tag,
            "--tag-object-sha",
            self.args.tag_object_sha,
            "--commit",
            self.args.commit,
            "--tree",
            self.args.tree,
            "--phase1-run-id",
            str(self.args.phase1_run_id),
            "--phase1-run-attempt",
            str(self.args.phase1_run_attempt),
            "--phase1-artifact-id",
            str(self.args.phase1_artifact_id),
            "--phase1-artifact-digest",
            self.args.phase1_artifact_digest,
            "--candidate-identity",
            json.dumps(candidate_identity, sort_keys=True, separators=(",", ":")),
            "--challenge",
            self.args.challenge,
            "--workflow-run-id",
            str(self.args.workflow_run_id),
            "--workflow-run-attempt",
            str(self.args.workflow_run_attempt),
            "--dispatch-ref",
            self.args.dispatch_ref,
            "--dispatch-sha",
            self.args.dispatch_sha,
            "--workflow-ref",
            self.args.workflow_ref,
            "--workflow-sha",
            self.args.workflow_sha,
        ]
        parsed = broker_parser().parse_args(argv)
        self.assertEqual(parsed.command, "recover-abort")
        self.assertFalse(hasattr(parsed, "output"))
        with (
            mock.patch("cag_round9_eval_broker.os.geteuid", return_value=1000),
            mock.patch("cag_round9_eval_broker.sys.stderr", new=io.StringIO()),
        ):
            self.assertEqual(broker_main(argv), 1)

    def test_stored_result_reuse_rejects_development_or_counted_mock_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / ("a" * 64)
            state.mkdir()
            (state / "round9-external-evaluation.json").write_text("{}\n", encoding="utf-8")
            (state / "round9-external-ledger-proof.json").write_text("{}\n", encoding="utf-8")
            token = root / "token"
            token.write_text("token\n", encoding="ascii")
            candidate = {"commit": self.args.commit}
            evaluator = {"version": "evaluator"}
            corpus = {"bundle_sha256": "a" * 64}
            execution = {"identity": "execution"}
            development = development_evidence(
                tag_object_sha=self.args.tag_object_sha,
                commit=self.args.commit,
                tree=self.args.tree,
                classifier_version=self.args.classifier_policy_version,
                classifier_sha256=self.args.classifier_policy_sha256,
                ruleset_version=self.args.ruleset_version,
                ruleset_sha256=self.args.ruleset_sha256,
            )
            counted = {"identity": "counted"}
            public_counted = public_counted_mock()
            ledger = {
                "repository": self.args.repository,
                "namespace": "round9-eval-ledger/" + "a" * 64,
                "reserved_ref": "refs/tags/round9-eval-ledger/" + "a" * 64 + "/reserved",
                "started_ref": "refs/tags/round9-eval-ledger/" + "a" * 64 + "/started",
                "result_ref": "refs/tags/round9-eval-ledger/" + "a" * 64 + "/result",
            }
            base_payload = {
                "candidate": candidate,
                "evaluator": evaluator,
                "corpus": corpus,
                "execution": execution,
                "ledger": ledger,
                "development_evidence": development,
                "counted_mock": counted,
                "public_counted_mock": public_counted,
                "metrics": {"identity": "metrics"},
            }

            class FakeClient:
                def __init__(self, *_args: object, **_kwargs: object):
                    pass

                def ref(self, *_args: object, **_kwargs: object) -> dict:
                    return {"object": {"type": "tag"}}

            config = {
                "repository": self.args.repository,
                "github": {"token_file": str(token), "api_url": "https://api.github.com"},
                "signing": {"public_key": str(root / "public.pem")},
                "identities": {"evaluator_key_id": "round9-evaluator-key-v1"},
                "_work_root": root,
                "_state_root": root,
                "_openssl": Path("/usr/bin/openssl"),
            }
            assets = {
                "so_sha256": self.args.so_sha256,
                "classifier_policy_version": self.args.classifier_policy_version,
                "classifier_policy_sha256": self.args.classifier_policy_sha256,
                "ruleset_version": self.args.ruleset_version,
                "ruleset_sha256": self.args.ruleset_sha256,
                "ruleset_manifest_sha256": self.args.ruleset_manifest_sha256,
                "build_metadata_sha256": self.args.build_metadata_sha256,
                "release_manifest_sha256": self.args.release_manifest_sha256,
            }
            for field in (
                "development_evidence",
                "counted_mock",
                "public_counted_mock",
            ):
                payload = copy.deepcopy(base_payload)
                payload[field] = {"identity": "drifted"}
                with (
                    mock.patch("cag_round9_eval_broker.read_secret", return_value="token"),
                    mock.patch("cag_round9_eval_broker.GitHubClient", FakeClient),
                    mock.patch("cag_round9_eval_broker.verify_remote_identity"),
                    mock.patch("cag_round9_eval_broker.verify_ledger_ruleset"),
                    mock.patch("cag_round9_eval_broker.corpus_identity", return_value=corpus),
                    mock.patch(
                        "cag_round9_eval_broker.verify_phase1_assets",
                        return_value=(root / "candidate.so", assets, development),
                    ),
                    mock.patch("cag_round9_eval_broker.candidate_identity", return_value=candidate),
                    mock.patch("cag_round9_eval_broker.evaluator_identity", return_value=evaluator),
                    mock.patch("cag_round9_eval_broker.execution_identity", return_value=execution),
                    mock.patch("cag_round9_eval_broker.validate_development_evidence"),
                    mock.patch(
                        "cag_round9_eval_broker.safe_extract_public_development_corpus",
                        return_value=public_counted["manifest"],
                    ),
                    mock.patch(
                        "cag_round9_eval_broker.load_canonical_json",
                        side_effect=lambda path, _label: {"payload": payload}
                        if path.name == "round9-external-evaluation.json"
                        else {"proof": True},
                    ),
                    mock.patch(
                        "cag_round9_eval_broker.verify_signed_envelope",
                        return_value=payload,
                    ),
                    mock.patch("cag_round9_eval_broker.validate_evaluation_payload"),
                    mock.patch(
                        "cag_round9_eval_broker.derive_counted_mock",
                        return_value=counted,
                    ),
                    mock.patch(
                        "cag_round9_eval_broker.validate_public_counted_mock",
                        return_value=public_counted,
                    ),
                ):
                    with self.assertRaisesRegex(ContractError, "stored completed"):
                        evaluate_once(config, self.args)


if __name__ == "__main__":
    unittest.main()
