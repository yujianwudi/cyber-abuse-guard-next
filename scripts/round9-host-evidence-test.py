#!/usr/bin/env python3
"""Offline contract tests for the Round 9 Host runner/assembler."""

from __future__ import annotations

import argparse
import errno
import hashlib
import http.server
import ipaddress
import importlib.util
import io
import json
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("round9_host_evidence.py")
REPO_ROOT = SCRIPT.parent.parent
COUNTED_MOCK_DOCKERFILE = REPO_ROOT / "integration" / "round9countedmock" / "Dockerfile"
HOST_IMAGE_BUILDER = REPO_ROOT / "scripts" / "round9-build-host-images.sh"
COUNTED_MOCK_BUILDER = (
    "docker.io/library/golang:1.26.4-bookworm@"
    "sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b"
)
SPEC = importlib.util.spec_from_file_location("round9_host_evidence", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Round 9 Host runner")
r8 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r8)

COMMIT = "1" * 40
TREE = "2" * 40


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_sidecar(path: Path) -> None:
    path.with_name(path.name + ".sha256").write_bytes(
        f"{digest(path)}  {path.name}\n".encode("utf-8")
    )


def make_base_bundle(root: Path) -> tuple[Path, Path]:
    archive = root / r8.BASE_ARCHIVE_NAME
    archive.write_bytes(b"synthetic-attested-linux-amd64-docker-save")
    manifest = root / r8.BASE_MANIFEST_NAME
    manifest.write_bytes(r8.canonical_bytes(r8.expected_base_image_bundle(digest(archive), archive.stat().st_size)))
    return manifest, archive


def fixture_document() -> dict[str, object]:
    return {
        "schema": "round8-balanced-readmission/v1",
        "pairs": [
            {
                "family": f"family_{index:02d}",
                "provenance": "synthetic_from_production_fp_family",
                "rule_id": "EVADE-002",
                "category": "defense_evasion",
                "benign": f"Synthetic benign fixture {index}",
                "malicious": f"Synthetic malicious fixture {index}",
            }
            for index in range(42)
        ],
    }


def make_source(path: Path, restricted: str | None = None) -> None:
    fixture = json.dumps(fixture_document(), separators=(",", ":")).encode()
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo(
            f"cyber-abuse-guard-v{r8.ARTIFACT_VERSION}/testdata/round8_balanced_readmission.json"
        )
        info.size = len(fixture)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(fixture))
        if restricted is not None:
            hidden = b"not release material"
            info = tarfile.TarInfo(
                f"cyber-abuse-guard-v{r8.ARTIFACT_VERSION}/{restricted}/secret.json"
            )
            info.size = len(hidden)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(hidden))


def refresh_checksums(root: Path) -> None:
    names = list(r8.PHASE1_CHECKSUM_NAMES)
    (root / "checksums.txt").write_bytes(
        "".join(f"{digest(root / name)}  {name}\n" for name in names).encode(
            "utf-8"
        )
    )


def make_artifacts(root: Path, restricted_source: str | None = None) -> None:
    so = root / r8.SO_NAME
    so.write_bytes(b"synthetic-linux-amd64-so")
    write_sidecar(so)
    store = root / r8.STORE_NAME
    with zipfile.ZipFile(store, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(r8.SO_NAME, so.read_bytes())
    with zipfile.ZipFile(root / r8.AUDIT_BUNDLE_NAME, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", b"synthetic audit bundle")
    (root / "build-metadata.json").write_bytes(
        r8.canonical_bytes({"commit": COMMIT, "tree": TREE})
    )
    (root / "ruleset-manifest.json").write_bytes(
        r8.canonical_bytes({"ruleset_version": "1.0.9"})
    )
    (root / "ruleset.sha256").write_text("a" * 64 + "\n", encoding="utf-8")
    (root / "sbom.cdx.json").write_bytes(
        r8.canonical_bytes({"bomFormat": "CycloneDX", "specVersion": "1.6"})
    )
    (root / r8.TEST_SUMMARY_NAME).write_text("synthetic test summary\n", encoding="utf-8")
    write_sidecar(root / r8.TEST_SUMMARY_NAME)
    (root / r8.RELEASE_EVIDENCE_NAME).write_text(
        "# Synthetic release evidence\n", encoding="utf-8"
    )
    write_sidecar(root / r8.RELEASE_EVIDENCE_NAME)
    source = root / r8.SOURCE_NAME
    make_source(source, restricted_source)
    write_sidecar(source)
    manifest = {
        "schema_version": 4,
        "release_phase": "candidate",
        "publish_rc_release": False,
        "artifact_version": r8.ARTIFACT_VERSION,
        "tag": r8.TAG,
        "commit": COMMIT,
        "tree": TREE,
    }
    (root / "rc-release-manifest.json").write_bytes(r8.canonical_bytes(manifest))
    write_sidecar(root / "rc-release-manifest.json")
    refresh_checksums(root)


def base_record(lane: str, check: str, **values: object) -> dict[str, object]:
    if values.get("status") == 200 and values.get("upstream_delta") == 1:
        values.setdefault("response_format", True)
        values.setdefault("termination_marker", True)
    return {"check": check, "lane": lane, **values}


def valid_records(
    lane: str,
    so_sha: str = "e" * 64,
    mock_image_id: str = "sha256:" + "c" * 64,
    cpa_image_id: str = "sha256:" + "d" * 64,
    cpa_build_date: str = "2026-01-02T03:04:05Z",
) -> list[dict[str, object]]:
    if lane != "primary":
        raise ValueError("tests only model the pinned CPA v7.2.113 primary lane")
    records: list[dict[str, object]] = []
    version, commit = r8.PRIMARY_VERSION, r8.PRIMARY_COMMIT
    records.extend(
        [
            base_record(
                lane,
                "artifact",
                case="exact_store_so",
                so_sha256=so_sha,
                config_sha256="f" * 64,
                plugin_path=f"plugins/linux/amd64/{r8.SO_NAME}",
                passed=True,
            ),
            base_record(
                lane,
                "mock_contract",
                case="health_reset_stats",
                contract=r8.MOCK_CONTRACT,
                source=r8.MOCK_SOURCE,
                revision=COMMIT,
                tag=r8.TAG,
                tree=TREE,
                image_id=mock_image_id,
                passed=True,
            ),
        ]
    )
    records.append(
        base_record(
            lane,
            "runtime_identity",
            case="cpa_image",
            version=version,
            commit=commit,
            build_date=cpa_build_date,
            image_id=cpa_image_id,
            passed=True,
        )
    )
    records.append(
        base_record(
            lane,
            "network_binding",
            case="cpa_management_and_api",
            host_ip=r8.CPA_NETWORK_MODE,
            host_port=r8.CPA_NETWORK_HOST_PORT,
            container_port=r8.CPA_PORT,
            passed=True,
        )
    )
    for protocol in ("chat", "responses"):
        records.append(base_record(lane, "protocol", protocol=protocol, case="benign", stream=False, status=200, upstream_delta=1, passed=True))
        records.append(base_record(lane, "protocol", protocol=protocol, case="malicious", stream=False, status=403, upstream_delta=0, passed=True))
    for pair in fixture_document()["pairs"]:  # type: ignore[index]
        family = pair["family"]  # type: ignore[index]
        records.append(base_record(lane, "matrix", family=family, case="benign", status=200, upstream_delta=1, passed=True))
        records.append(base_record(lane, "matrix", family=family, case="malicious", status=403, upstream_delta=0, passed=True))
    for protocol in ("chat", "responses"):
        for stream in (False, True):
            records.append(base_record(lane, "transport", protocol=protocol, case="benign", stream=stream, status=200, upstream_delta=1, passed=True))
            records.append(base_record(lane, "transport", protocol=protocol, case="malicious", stream=stream, status=403, upstream_delta=0, passed=True))
    for mode, case, status, delta in (
        ("audit", "malicious", 200, 1),
        ("balanced", "benign", 200, 1),
        ("balanced", "malicious", 403, 0),
        ("strict", "benign", 200, 1),
        ("strict", "malicious", 403, 0),
    ):
        records.append(base_record(lane, "mode", mode=mode, case=case, status=status, upstream_delta=delta, passed=True))
    for case, status, delta, queue in (
        ("balanced_incomplete", 200, 1, None),
        ("strict_incomplete", 403, 0, None),
        ("usage_allow", 200, 1, 1),
        ("usage_blocked", 403, 0, 0),
    ):
        values: dict[str, object] = {"case": case, "status": status, "upstream_delta": delta, "passed": True}
        if case in {"balanced_incomplete", "strict_incomplete"}:
            values.update(
                request_sha256="c" * 64,
                request_bytes=r8.SCAN_LIMIT_BYTES + 1024,
                scan_limit_bytes=r8.SCAN_LIMIT_BYTES,
                valid_json=True,
            )
        if queue is not None:
            values["queue_count"] = queue
        records.append(base_record(lane, "policy", **values))
    for protocol in ("chat", "responses"):
        records.append(base_record(lane, "tool_schema", protocol=protocol, case="benign", status=200, upstream_delta=1, passed=True))
        records.append(base_record(lane, "tool_schema", protocol=protocol, case="malicious", status=403, upstream_delta=0, passed=True))
    records.extend(
        [
            base_record(lane, "raw_capture", case="only_blocked", benign_captures=0, blocked_captures=1, passed=True),
            base_record(lane, "raw_capture", case="ttl_dedup", deduplicated=1, ttl_removed=1, passed=True),
            base_record(lane, "raw_capture", case="schema_v4_redaction_metadata", schema_version=4, redaction_applied=True, redaction_hits=1, passed=True),
            base_record(lane, "raw_capture", case="purge_wal", purge_removed=1, wal_busy=0, passed=True),
            base_record(lane, "database", case="final", quick_check="ok", schema_version=6, migration_versions="1,2,3,4,5,6", wal_busy=0, wal_log_frames=0, wal_checkpointed_frames=0, passed=True),
            base_record(lane, "controlled_restart", case="ttl", stopped_exit_code=0, running=True, restart_count=0, exit_code=0, oom=False, passed=True),
            base_record(lane, "lifecycle", case="final", restart_count=0, exit_code=0, oom=False, panic_count=0, fatal_count=0, plugin_error_count=0, passed=True),
            base_record(lane, "safety", case="network_isolation", real_provider_contacted=False, production_accessed=False, passed=True),
        ]
    )
    return records


def make_lane_result(root: Path, artifacts: Path, execution_id: str) -> Path:
    lane = "primary"
    lane_root = root / lane
    lane_root.mkdir()
    version, cpa_commit = r8.PRIMARY_VERSION, r8.PRIMARY_COMMIT
    so_sha = digest(artifacts / r8.SO_NAME)
    mock_image_id = "sha256:" + "c" * 64
    cpa_image_id = "sha256:" + "a" * 64
    cpa_build_date = "2026-01-02T03:04:05Z"
    records = valid_records(
        lane, so_sha, mock_image_id, cpa_image_id, cpa_build_date
    )
    transcript = lane_root / "transcript.jsonl"
    transcript.write_bytes(
        b"".join(r8.canonical_bytes(record) + b"\n" for record in records)
    )
    families = [pair["family"] for pair in fixture_document()["pairs"]]  # type: ignore[index]
    host_results, safety = r8.derive_host_results(records, families, lane)
    result = {
        "schema_version": 1,
        "runner": {
            "name": "round9-host-runner",
            "version": r8.RUNNER_VERSION,
            "execution_id": execution_id,
            "lane": lane,
        },
        "candidate": {
            "tag": r8.TAG,
            "commit": COMMIT,
            "tree": TREE,
            "so_name": r8.SO_NAME,
            "so_sha256": digest(artifacts / r8.SO_NAME),
        },
        "cpa": {
            "version": version,
            "commit": cpa_commit,
            "image": f"local/cpa:{version}",
            "image_id": cpa_image_id,
            "build_date": cpa_build_date,
        },
        "mock": r8.closed_mock_identity(mock_image_id, COMMIT, TREE),
        "host_results": host_results,
        "safety": safety,
        "transcript": {
            "path": str(transcript.resolve()),
            "sha256": digest(transcript),
            "records": len(records),
        },
    }
    path = lane_root / "lane-result.json"
    path.write_bytes(r8.canonical_bytes(result))
    return path


def make_execution_binding(execution_id: str) -> dict[str, object]:
    return {
        "trust": "GITHUB_ATTESTED_ROUND9_HOST_WORKFLOW",
        "challenge": "d" * 64,
        "execution_id": execution_id,
        "started_at": "2026-07-23T00:00:00Z",
        "completed_at": "2026-07-23T00:01:00Z",
        "workflow": {
            "repository": r8.WORKFLOW_REPOSITORY,
            "path": r8.HOST_WORKFLOW_PATH,
            "ref": f"refs/tags/{r8.TAG}",
            "sha": COMMIT,
            "run_id": 10,
            "run_attempt": 1,
        },
        "phase1": {
            "workflow_path": r8.RELEASE_WORKFLOW_PATH,
            "run_id": 11,
            "run_attempt": 1,
            "artifact_id": 12,
            "artifact_digest": "sha256:" + "e" * 64,
        },
        "runner": {
            "name": "round9-test-runner",
            "environment": "self-hosted",
            "os": "Linux",
            "arch": "X64",
        },
        "sandbox": {
            "sandbox_id": "round9-sandbox",
            "daemon_id": "round9-daemon",
            "daemon_label": "io.cyber-abuse-guard.round9-sandbox=round9-sandbox",
            "production_label": "io.cyber-abuse-guard.production=false",
            "probe_image_id": "sha256:" + "7" * 64,
            "locality_challenge": "PASS",
        },
    }


class Round9HostEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        make_artifacts(self.artifacts)
        execution_id = str(uuid.uuid4())
        self.primary = make_lane_result(self.root, self.artifacts, execution_id)
        self.execution = make_execution_binding(execution_id)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_counted_mock_builder_is_canonical_and_digest_pinned(self) -> None:
        first_line = COUNTED_MOCK_DOCKERFILE.read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(first_line, f"FROM {COUNTED_MOCK_BUILDER} AS builder")

    def test_attested_base_bundle_contract_is_canonical_and_digest_closed(self) -> None:
        manifest, archive = make_base_bundle(self.root)
        self.assertEqual(r8.validate_base_image_bundle(manifest, archive), digest(archive))
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(payload["images"]["golang"], r8.GOLANG_BASE)
        self.assertEqual(payload["images"]["debian"], r8.DEBIAN_BASE)
        self.assertEqual(payload["acquisition"]["relay"], r8.BASE_TRANSPORT)

    def test_attested_base_bundle_rejects_identity_size_and_framing_drift(self) -> None:
        manifest, archive = make_base_bundle(self.root)
        original = manifest.read_bytes()
        payload = json.loads(original)
        mutations = (
            ("golang index", lambda value: value["images"]["golang"].__setitem__("index_digest", "sha256:" + "0" * 64)),
            ("debian image", lambda value: value["images"]["debian"].__setitem__("image_id", "sha256:" + "1" * 64)),
            ("transport", lambda value: value["acquisition"].__setitem__("relay", "unreviewed-proxy")),
            ("archive size", lambda value: value["archive"].__setitem__("size", value["archive"]["size"] + 1)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                changed = json.loads(original)
                mutate(changed)
                manifest.write_bytes(r8.canonical_bytes(changed))
                with self.assertRaises(r8.RunnerError):
                    r8.validate_base_image_bundle(manifest, archive)
        manifest.write_bytes(original + b"\n")
        with self.assertRaises(r8.RunnerError):
            r8.validate_base_image_bundle(manifest, archive)

    def test_host_builder_uses_only_loaded_exact_base_images(self) -> None:
        text = HOST_IMAGE_BUILDER.read_text(encoding="utf-8")
        for expected in (
            r8.PRIMARY_VERSION,
            r8.PRIMARY_COMMIT,
            r8.GOLANG_BASE["canonical_reference"],
            r8.GOLANG_BASE["platform_digest"],
            r8.GOLANG_BASE["image_id"],
            r8.GOLANG_BASE["local_tag"],
            r8.DEBIAN_BASE["canonical_reference"],
            r8.DEBIAN_BASE["platform_digest"],
            r8.DEBIAN_BASE["image_id"],
            r8.DEBIAN_BASE["local_tag"],
            "validate-base-bundle",
            'docker load --input "$base_images_archive"',
        ):
            self.assertIn(expected, text)
        self.assertEqual(text.count("docker build --pull=false --platform linux/amd64"), 2)
        self.assertEqual(text.count('build_cpa_image "$primary_version"'), 1)
        self.assertNotIn("COMPATIBILITY_IMAGE", text)
        self.assertNotIn("v7.2.88", text)
        self.assertNotIn("docker build --pull --platform", text)
        self.assertNotIn("public.ecr.aws", text)

    def assemble(self) -> Path:
        output = self.root / ("output-" + uuid.uuid4().hex)
        r8.verify_artifact_and_assemble(
            self.artifacts,
            self.primary,
            output,
            COMMIT,
            TREE,
            self.execution,
        )
        return output / "round9-host-evidence.json"

    def test_canonical_evidence_and_base64_have_no_trailing_newline(self) -> None:
        evidence = self.assemble()
        self.assertFalse(evidence.read_bytes().endswith(b"\n"))
        encoded = evidence.with_name("round9-host-evidence.json.b64").read_bytes()
        self.assertFalse(encoded.endswith(b"\n"))
        self.assertEqual(r8.validate_final_evidence(evidence, self.artifacts, COMMIT, TREE), digest(evidence))

    def test_final_validator_rejects_schema1_even_with_execution(self) -> None:
        evidence = self.assemble()
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        payload["schema_version"] = 1
        evidence.write_bytes(r8.canonical_bytes(payload))
        with self.assertRaisesRegex(r8.RunnerError, "schema 2 with an execution binding"):
            r8.validate_final_evidence(evidence, self.artifacts, COMMIT, TREE)

    def test_final_validator_rejects_schema2_without_execution(self) -> None:
        evidence = self.assemble()
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        del payload["execution"]
        evidence.write_bytes(r8.canonical_bytes(payload))
        with self.assertRaisesRegex(r8.RunnerError, "execution binding schema"):
            r8.validate_final_evidence(evidence, self.artifacts, COMMIT, TREE)

    def test_assembler_rejects_execution_id_different_from_runner_lane(self) -> None:
        execution = json.loads(json.dumps(self.execution))
        execution["execution_id"] = str(uuid.uuid4())
        with self.assertRaisesRegex(
            r8.RunnerError,
            "execution binding does not match the primary runner lane",
        ):
            r8.verify_artifact_and_assemble(
                self.artifacts,
                self.primary,
                self.root / "mismatched-execution-output",
                COMMIT,
                TREE,
                execution,
            )

    def test_parser_does_not_expose_unattested_assemble_command(self) -> None:
        subparsers = next(
            action
            for action in r8.parser()._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        self.assertNotIn("assemble", subparsers.choices)

    def test_validate_cli_does_not_claim_host_pass_or_attestation(self) -> None:
        evidence = self.assemble()
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            status = r8.main(
                [
                    "validate",
                    "--artifacts",
                    str(self.artifacts),
                    "--evidence",
                    str(evidence),
                    "--commit",
                    COMMIT,
                    "--tree",
                    TREE,
                ]
            )
        rendered = output.getvalue()
        self.assertEqual(status, 0)
        self.assertIn("SCHEMA_VALID_ATTESTATION_EXTERNAL", rendered)
        self.assertNotIn("PASS", rendered)
        self.assertNotIn("ATTESTED", rendered)

    def test_exact_phase1_artifact_set_needs_no_store_sidecar(self) -> None:
        self.assertFalse((self.artifacts / f"{r8.STORE_NAME}.sha256").exists())
        self.assertEqual(
            {path.name for path in self.artifacts.iterdir()}, r8.PHASE1_ASSET_NAMES
        )
        self.assertEqual(len(r8.PHASE1_ASSET_NAMES), 17)
        _, so_sha, fixtures = r8.verify_artifacts(self.artifacts, COMMIT, TREE)
        self.assertEqual(so_sha, digest(self.artifacts / r8.SO_NAME))
        self.assertEqual(len(fixtures), 42)

    def test_phase1_artifact_set_rejects_any_extra_asset(self) -> None:
        (self.artifacts / "unexpected.txt").write_text("extra\n", encoding="utf-8")
        with self.assertRaises(r8.RunnerError):
            r8.verify_artifacts(self.artifacts, COMMIT, TREE)

    def test_manifest_sidecar_is_mandatory(self) -> None:
        (self.artifacts / "rc-release-manifest.json.sha256").unlink()
        with self.assertRaises(r8.RunnerError):
            r8.verify_artifacts(self.artifacts, COMMIT, TREE)

    def test_final_schema_rejects_extra_missing_and_type_drift(self) -> None:
        for mutation in ("extra", "missing", "type"):
            with self.subTest(mutation=mutation):
                evidence = self.assemble()
                payload = json.loads(evidence.read_text(encoding="utf-8"))
                if mutation == "extra":
                    payload["manual_pass"] = True
                elif mutation == "missing":
                    del payload["safety"]
                else:
                    payload["cpa"]["primary"]["host_results"]["protocol_requests"]["chat_benign_upstream"] = True
                evidence.write_bytes(r8.canonical_bytes(payload))
                with self.assertRaises(r8.RunnerError):
                    r8.validate_final_evidence(evidence, self.artifacts, COMMIT, TREE)

    def test_final_schema_rejects_invalid_counted_mock_image_identity(self) -> None:
        evidence = self.assemble()
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        payload["mock"]["image_id"] = "sha256:not-a-digest"
        evidence.write_bytes(r8.canonical_bytes(payload))
        with self.assertRaises(r8.RunnerError):
            r8.validate_final_evidence(evidence, self.artifacts, COMMIT, TREE)

    def test_final_schema_rejects_retired_compatibility_lane(self) -> None:
        evidence = self.assemble()
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        payload["cpa"]["compatibility"] = dict(payload["cpa"]["primary"])
        evidence.write_bytes(r8.canonical_bytes(payload))
        with self.assertRaises(r8.RunnerError):
            r8.validate_final_evidence(evidence, self.artifacts, COMMIT, TREE)

    def test_final_schema_rejects_unicode_digit_build_date(self) -> None:
        evidence = self.assemble()
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        payload["cpa"]["primary"]["build_date"] = "２０２６-０１-０２T０３:０４:０５Z"
        evidence.write_bytes(r8.canonical_bytes(payload))
        with self.assertRaises(r8.RunnerError):
            r8.validate_final_evidence(evidence, self.artifacts, COMMIT, TREE)

    def test_final_validator_rejects_noncanonical_json(self) -> None:
        evidence = self.assemble()
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        evidence.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        with self.assertRaises(r8.RunnerError):
            r8.validate_final_evidence(evidence, self.artifacts, COMMIT, TREE)

    def test_so_hash_mismatch_is_rejected(self) -> None:
        (self.artifacts / r8.SO_NAME).write_bytes(b"changed")
        with self.assertRaises(r8.RunnerError):
            r8.verify_artifact_and_assemble(
                self.artifacts, self.primary, self.root / "out", COMMIT, TREE, self.execution
            )

    def test_store_so_mismatch_is_rejected_even_with_refreshed_archive_hashes(self) -> None:
        store = self.artifacts / r8.STORE_NAME
        with zipfile.ZipFile(store, "w") as archive:
            archive.writestr(r8.SO_NAME, b"different-so")
        refresh_checksums(self.artifacts)
        with self.assertRaises(r8.RunnerError):
            r8.verify_artifacts(self.artifacts, COMMIT, TREE)

    def test_transcript_hash_mismatch_is_rejected(self) -> None:
        payload = json.loads(self.primary.read_text(encoding="utf-8"))
        Path(payload["transcript"]["path"]).write_bytes(b"{}\n")
        with self.assertRaises(r8.RunnerError):
            r8.verify_artifact_and_assemble(
                self.artifacts, self.primary, self.root / "out", COMMIT, TREE, self.execution
            )

    def test_hand_filled_pass_without_machine_transcript_is_rejected(self) -> None:
        payload = json.loads(self.primary.read_text(encoding="utf-8"))
        payload["transcript"] = {
            "path": str((self.root / "missing.jsonl").resolve()),
            "sha256": "0" * 64,
            "records": 111,
        }
        self.primary.write_bytes(r8.canonical_bytes(payload))
        with self.assertRaises(r8.RunnerError):
            r8.verify_artifact_and_assemble(
                self.artifacts, self.primary, self.root / "out", COMMIT, TREE, self.execution
            )

    def test_deriver_requires_malicious_stream_and_nonstream_for_both_apis(self) -> None:
        records = valid_records("primary")
        records = [
            record
            for record in records
            if not (
                record.get("check") == "transport"
                and record.get("protocol") == "responses"
                and record.get("case") == "malicious"
                and record.get("stream") is True
            )
        ]
        families = [pair["family"] for pair in fixture_document()["pairs"]]  # type: ignore[index]
        with self.assertRaises(r8.RunnerError):
            r8.derive_host_results(records, families, "primary")

    def test_deriver_requires_valid_over_limit_incomplete_request(self) -> None:
        records = valid_records("primary")
        for record in records:
            if record.get("check") == "policy" and record.get("case") == "balanced_incomplete":
                record["request_bytes"] = r8.SCAN_LIMIT_BYTES
        families = [pair["family"] for pair in fixture_document()["pairs"]]  # type: ignore[index]
        with self.assertRaises(r8.RunnerError):
            r8.derive_host_results(records, families, "primary")

    def test_deriver_requires_exact_migration_history_one_through_five(self) -> None:
        records = valid_records("primary")
        for record in records:
            if record.get("check") == "database":
                record["migration_versions"] = "1,2,3,5"
        families = [pair["family"] for pair in fixture_document()["pairs"]]  # type: ignore[index]
        with self.assertRaises(r8.RunnerError):
            r8.derive_host_results(records, families, "primary")

    def test_deriver_requires_exact_artifact_and_counted_mock_records(self) -> None:
        families = [pair["family"] for pair in fixture_document()["pairs"]]  # type: ignore[index]
        for missing in ("artifact", "mock_contract"):
            with self.subTest(missing=missing):
                records = [
                    record
                    for record in valid_records("primary")
                    if record.get("check") != missing
                ]
                with self.assertRaises(r8.RunnerError):
                    r8.derive_host_results(records, families, "primary")

    def test_deriver_requires_exactly_one_successful_controlled_restart(self) -> None:
        families = [pair["family"] for pair in fixture_document()["pairs"]]  # type: ignore[index]
        for mutation in ("missing", "failed", "duplicate"):
            with self.subTest(mutation=mutation):
                records = valid_records("primary")
                restart = next(
                    record
                    for record in records
                    if record.get("check") == "controlled_restart"
                )
                if mutation == "missing":
                    records.remove(restart)
                elif mutation == "failed":
                    restart["passed"] = False
                else:
                    records.append(dict(restart))
                with self.assertRaises(r8.RunnerError):
                    r8.derive_host_results(records, families, "primary")

    def test_deriver_rejects_any_non_contract_cpa_network_binding(self) -> None:
        families = [pair["family"] for pair in fixture_document()["pairs"]]  # type: ignore[index]
        records = valid_records("primary")
        binding = next(
            record for record in records if record.get("check") == "network_binding"
        )
        binding["host_port"] = 1
        with self.assertRaisesRegex(r8.RunnerError, "network binding observation"):
            r8.derive_host_results(records, families, "primary")

    def test_lane_result_cpa_identity_must_match_runtime_transcript(self) -> None:
        payload = json.loads(self.primary.read_text(encoding="utf-8"))
        payload["cpa"]["image_id"] = "sha256:" + "9" * 64
        self.primary.write_bytes(r8.canonical_bytes(payload))
        with self.assertRaises(r8.RunnerError):
            r8.verify_artifact_and_assemble(
                self.artifacts,
                self.primary,
                self.root / "out",
                COMMIT,
                TREE,
                self.execution,
            )

    def test_transcript_loader_rejects_noncanonical_json_line(self) -> None:
        path = self.root / "pretty-transcript.jsonl"
        record = base_record("primary", "safety", case="network_isolation", passed=True)
        path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaises(r8.RunnerError):
            r8.load_transcript(path, "primary")

    def test_source_archive_rejects_all_restricted_material_classes(self) -> None:
        source = self.artifacts / r8.SOURCE_NAME
        for restricted in (
            "evaluation-v11",
            "holdout-v4",
            "consumed-corpus",
            "private-payload",
            "blind-review",
            "retired-fixture",
        ):
            with self.subTest(restricted=restricted):
                make_source(source, restricted=restricted)
                write_sidecar(source)
                refresh_checksums(self.artifacts)
                with self.assertRaises(r8.RunnerError):
                    r8.verify_artifacts(self.artifacts, COMMIT, TREE)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        evidence = self.assemble()
        evidence.write_bytes(b'{"schema_version":1,"schema_version":1}')
        with self.assertRaises(r8.RunnerError):
            r8.validate_final_evidence(evidence, self.artifacts, COMMIT, TREE)

    def test_linux_gate_fails_closed(self) -> None:
        with mock.patch.object(r8.platform, "system", return_value="Darwin"), mock.patch.object(
            r8.platform, "machine", return_value="arm64"
        ):
            with self.assertRaises(r8.RunnerError):
                r8.require_linux(argparse.Namespace(), self.root)

    def test_remote_docker_endpoints_are_rejected(self) -> None:
        for endpoint in (
            "tcp://127.0.0.1:2375",
            "ssh://sandbox.example",
            "https://docker.example",
            "npipe:////./pipe/docker_engine",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(r8.RunnerError):
                r8.require_local_unix_endpoint(endpoint, "test")

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
    def test_local_unix_docker_endpoint_contract(self) -> None:
        socket_path = self.root / "docker.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(socket_path))
            self.assertEqual(
                r8.require_local_unix_endpoint(f"unix://{socket_path}", "test"),
                socket_path,
            )
        finally:
            server.close()

    def sandbox_runner(
        self,
        *,
        daemon_id: str = "sandbox-daemon-0001",
        labels: list[str] | None = None,
        locality_matches: bool = True,
    ) -> tuple[socket.socket, list[list[str]], object]:
        socket_path = self.root / ("docker-" + uuid.uuid4().hex + ".sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        calls: list[list[str]] = []
        probe = "sha256:" + "a" * 64
        expected_labels = labels or [
            "io.cyber-abuse-guard.round9-sandbox=sandbox-test-0001",
            "io.cyber-abuse-guard.production=false",
        ]

        def runner(args: object, _label: str, _timeout: float, _check: bool) -> object:
            command = list(args)  # type: ignore[arg-type]
            calls.append(command)
            if command == ["context", "show"]:
                return r8.docker_sandbox.CommandResult(0, b"default\n", b"")
            if command == ["context", "inspect", "default"]:
                payload = [{"Endpoints": {"docker": {"Host": f"unix://{socket_path}"}}}]
                return r8.docker_sandbox.CommandResult(0, json.dumps(payload).encode(), b"")
            if command[:2] == ["info", "--format"]:
                payload = {"id": daemon_id, "os": "linux", "arch": "x86_64", "labels": expected_labels}
                return r8.docker_sandbox.CommandResult(0, json.dumps(payload).encode(), b"")
            if command == ["image", "inspect", probe]:
                payload = [{"Id": probe, "Os": "linux", "Architecture": "amd64"}]
                return r8.docker_sandbox.CommandResult(0, json.dumps(payload).encode(), b"")
            if command and command[0] == "create":
                return r8.docker_sandbox.CommandResult(0, b"b" * 64 + b"\n", b"")
            if command[:2] == ["start", "--attach"]:
                create = next(item for item in calls if item and item[0] == "create")
                mount = create[create.index("--mount") + 1]
                source = Path(mount.split(",")[1].removeprefix("src="))
                nonce = (source / "nonce").read_bytes()
                if not locality_matches:
                    nonce = b"forwarded-daemon-cannot-see-host-nonce\n"
                return r8.docker_sandbox.CommandResult(0, nonce, b"")
            if command[:2] == ["rm", "--force"]:
                return r8.docker_sandbox.CommandResult(0, b"", b"")
            raise AssertionError(command)

        return server, calls, runner

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
    def test_runner_rejects_daemon_identity_mismatch_before_container_actions(self) -> None:
        server, calls, runner = self.sandbox_runner(daemon_id="different-daemon-0001")
        clean_env = {
            key: value
            for key, value in os.environ.items()
            if key
            not in {
                "DOCKER_HOST",
                "DOCKER_CONTEXT",
                "DOCKER_TLS_VERIFY",
                "DOCKER_CERT_PATH",
            }
        }
        try:
            with mock.patch.dict(os.environ, clean_env, clear=True), mock.patch.object(
                r8.docker_sandbox.platform, "system", return_value="Linux"
            ), mock.patch.object(
                r8.docker_sandbox.platform, "machine", return_value="x86_64"
            ):
                with self.assertRaises(r8.docker_sandbox.SandboxError):
                    r8.docker_sandbox.verify_sandbox(
                        sandbox_id="sandbox-test-0001",
                        daemon_id="sandbox-daemon-0001",
                        probe_image_id="sha256:" + "a" * 64,
                        challenge="c" * 64,
                        challenge_root=self.root,
                        docker_runner=runner,  # type: ignore[arg-type]
                    )
            self.assertFalse(any(call and call[0] in {"create", "run", "build"} for call in calls))
            self.assertFalse(any(call[:2] == ["network", "create"] for call in calls))
        finally:
            server.close()

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
    def test_runner_rejects_missing_sandbox_label_before_container_actions(self) -> None:
        server, calls, runner = self.sandbox_runner(
            labels=["io.cyber-abuse-guard.production=false"]
        )
        try:
            with mock.patch.object(
                r8.docker_sandbox.platform, "system", return_value="Linux"
            ), mock.patch.object(
                r8.docker_sandbox.platform, "machine", return_value="x86_64"
            ), mock.patch.dict(
                os.environ,
                {key: value for key, value in os.environ.items() if not key.startswith("DOCKER_")},
                clear=True,
            ):
                with self.assertRaises(r8.docker_sandbox.SandboxError):
                    r8.docker_sandbox.verify_sandbox(
                        sandbox_id="sandbox-test-0001",
                        daemon_id="sandbox-daemon-0001",
                        probe_image_id="sha256:" + "a" * 64,
                        challenge="e" * 64,
                        challenge_root=self.root,
                        docker_runner=runner,  # type: ignore[arg-type]
                    )
            self.assertFalse(any(call and call[0] in {"create", "run", "build"} for call in calls))
        finally:
            server.close()

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
    def test_protected_sandbox_identity_and_locality_pass(self) -> None:
        server, calls, runner = self.sandbox_runner()
        try:
            with mock.patch.object(
                r8.docker_sandbox.platform, "system", return_value="Linux"
            ), mock.patch.object(
                r8.docker_sandbox.platform, "machine", return_value="x86_64"
            ), mock.patch.dict(
                os.environ,
                {key: value for key, value in os.environ.items() if not key.startswith("DOCKER_")},
                clear=True,
            ):
                identity = r8.docker_sandbox.verify_sandbox(
                    sandbox_id="sandbox-test-0001",
                    daemon_id="sandbox-daemon-0001",
                    probe_image_id="sha256:" + "a" * 64,
                    challenge="f" * 64,
                    challenge_root=self.root,
                    docker_runner=runner,  # type: ignore[arg-type]
                )
            self.assertEqual(identity["locality_challenge"], "PASS")
            self.assertEqual(identity["daemon_id"], "sandbox-daemon-0001")
            self.assertTrue(any(call and call[0] == "create" for call in calls))
            self.assertTrue(any(call[:2] == ["rm", "--force"] for call in calls))
        finally:
            server.close()

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
    def test_forwarded_unix_socket_fails_nonce_before_workload_actions(self) -> None:
        server, calls, runner = self.sandbox_runner(locality_matches=False)
        clean_env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}
        }
        try:
            with mock.patch.dict(os.environ, clean_env, clear=True), mock.patch.object(
                r8.docker_sandbox.platform, "system", return_value="Linux"
            ), mock.patch.object(
                r8.docker_sandbox.platform, "machine", return_value="x86_64"
            ):
                with self.assertRaises(r8.docker_sandbox.SandboxError):
                    r8.docker_sandbox.verify_sandbox(
                        sandbox_id="sandbox-test-0001",
                        daemon_id="sandbox-daemon-0001",
                        probe_image_id="sha256:" + "a" * 64,
                        challenge="d" * 64,
                        challenge_root=self.root,
                        docker_runner=runner,  # type: ignore[arg-type]
                    )
            self.assertTrue(any(call and call[0] == "create" for call in calls))
            self.assertTrue(any(call[:2] == ["start", "--attach"] for call in calls))
            self.assertFalse(any(call and call[0] in {"run", "build"} for call in calls))
            self.assertFalse(any(call[:2] == ["network", "create"] for call in calls))
        finally:
            server.close()

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires POSIX bash")
    def test_image_builder_rejects_remote_docker_context_before_git_or_build(self) -> None:
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        docker = fake_bin / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            "if [ \"$1 $2\" = \"context show\" ]; then echo default; exit 0; fi\n"
            "if [ \"$1 $2\" = \"context inspect\" ]; then echo '[{\"Endpoints\":{\"docker\":{\"Host\":\"tcp://remote.example:2375\"}}}]'; exit 0; fi\n"
            "exit 99\n",
            encoding="utf-8",
        )
        uname = fake_bin / "uname"
        uname.write_text(
            "#!/bin/sh\n[ \"$1\" = \"-s\" ] && echo Linux || echo x86_64\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        uname.chmod(0o755)
        env = {
            key: value
            for key, value in os.environ.items()
            if key
            not in {
                "DOCKER_HOST",
                "DOCKER_CONTEXT",
                "DOCKER_TLS_VERIFY",
                "DOCKER_CERT_PATH",
            }
        }
        env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
        script = SCRIPT.with_name("round9-build-host-images.sh")
        base_manifest, base_archive = make_base_bundle(self.root)
        result = subprocess.run(
            [
                "bash",
                str(script),
                "--execute",
                "--work",
                str(self.root / "work"),
                "--candidate-commit",
                COMMIT,
                "--candidate-tree",
                TREE,
                "--sandbox-id",
                "sandbox-test-0001",
                "--daemon-id",
                "sandbox-daemon-0001",
                "--probe-image-id",
                "sha256:" + "a" * 64,
                "--challenge",
                "c" * 64,
                "--base-images-archive",
                str(base_archive),
                "--base-images-manifest",
                str(base_manifest),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Unix Docker socket", result.stderr)

    def test_execute_acknowledgement_is_required_before_any_host_action(self) -> None:
        args = argparse.Namespace(execute=False)
        with self.assertRaises(r8.RunnerError):
            r8.run_primary_lane(args)

    def test_cpa_image_identity_requires_exact_oci_and_binary_line(self) -> None:
        build_date = "2026-01-02T03:04:05Z"
        image_id = "sha256:" + "a" * 64
        metadata = {
            "Os": "linux",
            "Architecture": "amd64",
            "Id": image_id,
            "Config": {
                "Labels": {
                    "org.opencontainers.image.source": r8.CPA_SOURCE,
                    "org.opencontainers.image.revision": r8.PRIMARY_COMMIT,
                    "org.opencontainers.image.version": r8.PRIMARY_VERSION,
                    "org.opencontainers.image.created": build_date,
                    **r8.cpa_base_labels(),
                }
            },
        }
        first_line = (
            f"CLIProxyAPI Version: {r8.PRIMARY_VERSION}, Commit: "
            f"{r8.PRIMARY_COMMIT}, BuiltAt: {build_date}\n"
        ).encode()
        probe = subprocess.CompletedProcess([], 0, stdout=first_line, stderr=b"")
        with mock.patch.object(r8, "image_metadata", return_value=metadata), mock.patch.object(
            r8, "docker", return_value=probe
        ):
            self.assertEqual(
                r8.verify_cpa_image("local/cpa:pinned", r8.PRIMARY_VERSION, r8.PRIMARY_COMMIT),
                (image_id, build_date),
            )
            base_key = "io.cyber-abuse-guard.round9.golang.image-id"
            metadata["Config"]["Labels"][base_key] = "sha256:" + "0" * 64
            with self.assertRaises(r8.RunnerError):
                r8.verify_cpa_image("local/cpa:pinned", r8.PRIMARY_VERSION, r8.PRIMARY_COMMIT)
            metadata["Config"]["Labels"][base_key] = r8.GOLANG_BASE["image_id"]
            probe.stdout = first_line.replace(b"BuiltAt:", b"BuiltAt: drift-")
            with self.assertRaises(r8.RunnerError):
                r8.verify_cpa_image("local/cpa:pinned", r8.PRIMARY_VERSION, r8.PRIMARY_COMMIT)

    def test_mock_image_identity_binds_source_revision_tag_and_tree(self) -> None:
        image_id = "sha256:" + "7" * 64
        labels = {
            "io.cyber-abuse-guard.round9.mock-contract": r8.MOCK_CONTRACT,
            "org.opencontainers.image.source": r8.MOCK_SOURCE,
            "org.opencontainers.image.revision": COMMIT,
            "org.opencontainers.image.version": r8.TAG,
            "io.cyber-abuse-guard.source-tree": TREE,
            **r8.golang_base_labels(),
        }
        metadata = {
            "Os": "linux",
            "Architecture": "amd64",
            "Id": image_id,
            "Config": {"Labels": labels},
        }
        with mock.patch.object(r8, "image_metadata", return_value=metadata):
            self.assertEqual(
                r8.verify_mock_image("local/mock:pinned", COMMIT, TREE),
                r8.closed_mock_identity(image_id, COMMIT, TREE),
            )
            labels["io.cyber-abuse-guard.round9.base-transport"] = "unreviewed-proxy"
            with self.assertRaises(r8.RunnerError):
                r8.verify_mock_image("local/mock:pinned", COMMIT, TREE)
            labels["io.cyber-abuse-guard.round9.base-transport"] = r8.BASE_TRANSPORT
            labels["io.cyber-abuse-guard.source-tree"] = "3" * 40
            with self.assertRaises(r8.RunnerError):
                r8.verify_mock_image("local/mock:pinned", COMMIT, TREE)

    def test_http_client_ignores_hostile_proxy_environment_and_requires_ipv4_loopback(self) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://example.invalid/leak")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            def log_message(self, format: str, *args: object) -> None:
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        hostile = {
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "ALL_PROXY": "http://127.0.0.1:1",
            "http_proxy": "http://127.0.0.1:1",
            "https_proxy": "http://127.0.0.1:1",
            "all_proxy": "http://127.0.0.1:1",
            "NO_PROXY": "",
            "no_proxy": "",
        }
        try:
            with mock.patch.dict(os.environ, hostile, clear=False):
                status, raw = r8.http_request(
                    f"http://127.0.0.1:{port}", "GET", "/healthz"
                )
                self.assertEqual((status, raw), (200, b'{"ok":true}'))
                query_status, query_raw = r8.http_request(
                    f"http://127.0.0.1:{port}",
                    "GET",
                    "/v0/management/usage-queue",
                    query=(("count", "100"),),
                )
                self.assertEqual((query_status, query_raw), (200, b'{"ok":true}'))
                redirect_status, _ = r8.http_request(
                    f"http://127.0.0.1:{port}", "GET", "/redirect"
                )
                self.assertEqual(redirect_status, 302)
                with self.assertRaises(r8.RunnerError):
                    r8.http_request(f"http://localhost:{port}", "GET", "/healthz")
                for base in (
                    "http://192.0.2.1:8317",
                    "http://169.254.1.2:8317",
                    "http://172.19.0.3:8443",
                    "http://[::1]:8317",
                    "http://172.19.0.3:not-a-port",
                ):
                    with self.subTest(base=base), self.assertRaises(r8.RunnerError):
                        r8.http_request(base, "GET", "/healthz")
                for unsafe_path in (
                    "/v0/management/usage-queue?count=100",
                    "/healthz#fragment",
                    "//other",
                    "http://example.invalid/leak",
                    "/%2f%2fexample.invalid/leak",
                ):
                    with self.subTest(path=unsafe_path), self.assertRaises(r8.RunnerError):
                        r8.http_request(
                            f"http://127.0.0.1:{port}", "GET", unsafe_path
                        )
                unsafe_queries = (
                    ("/healthz", (("count", "100"),)),
                    ("/v0/management/usage-queue", None),
                    (
                        "/v0/management/usage-queue",
                        (("count", "100"), ("count", "100")),
                    ),
                    ("/v0/management/usage-queue", (("unknown", "100"),)),
                    ("/v0/management/usage-queue", (("%63ount", "100"),)),
                    ("/v0/management/usage-queue", (("count", "%31%30%30"),)),
                    ("/v0/management/usage-queue", (("count", "0100"),)),
                    (
                        r8.MANAGEMENT_PATH + "/raw-captures",
                        (("limit", "100"), ("extra", "1")),
                    ),
                )
                for query_path, query in unsafe_queries:
                    with self.subTest(
                        query_path=query_path, query=query
                    ), self.assertRaises(r8.RunnerError):
                        r8.http_request(
                            f"http://127.0.0.1:{port}",
                            "GET",
                            query_path,
                            query=query,
                        )
                with self.assertRaises(r8.RunnerError):
                    r8.http_request(
                        f"http://127.0.0.1:{port}",
                        "POST",
                        "/v0/management/usage-queue",
                        query=(("count", "100"),),
                    )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_real_usage_and_raw_capture_consumers_use_fixed_query_contracts(self) -> None:
        requested: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                requested.append(self.path)
                if self.path == "/v0/management/usage-queue?count=100":
                    payload = []
                elif self.path == r8.MANAGEMENT_PATH + "/raw-captures?limit=100":
                    payload = {"captures": [], "returned_count": 0}
                else:
                    self.send_error(404)
                    return
                raw = r8.canonical_bytes(payload)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            lane = object.__new__(r8.Lane)
            lane.cpa_url = f"http://127.0.0.1:{server.server_address[1]}"
            lane.management_key = "test"
            lane.drain_usage_queue()
            self.assertEqual(
                lane.query_raw_captures(), {"captures": [], "returned_count": 0}
            )
            self.assertEqual(
                requested,
                [
                    "/v0/management/usage-queue?count=100",
                    r8.MANAGEMENT_PATH + "/raw-captures?limit=100",
                ],
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_container_private_ipv4_requires_exact_isolated_rfc1918_network(self) -> None:
        network = "cag-r9-primary-test-net"
        info = {
            "NetworkSettings": {
                "Networks": {network: {"IPAddress": "172.19.0.3"}},
                "Ports": {f"{r8.CPA_PORT}/tcp": None},
            },
            "HostConfig": {"PortBindings": {}, "PublishAllPorts": False},
        }
        self.assertEqual(
            r8.container_private_ipv4(info, network_name=network, role="cpa"),
            "172.19.0.3",
        )
        r8.verify_no_host_port_binding(info, role="cpa")
        for address in ("127.0.0.1", "169.254.1.2", "192.0.2.1", "::1", "invalid"):
            with self.subTest(address=address):
                mutated = json.loads(json.dumps(info))
                mutated["NetworkSettings"]["Networks"][network]["IPAddress"] = address
                with self.assertRaises(r8.RunnerError):
                    r8.container_private_ipv4(
                        mutated, network_name=network, role="cpa"
                    )
        escaped = json.loads(json.dumps(info))
        escaped["NetworkSettings"]["Networks"]["outside"] = {"IPAddress": "172.20.0.4"}
        with self.assertRaisesRegex(r8.RunnerError, "not attached only"):
            r8.container_private_ipv4(escaped, network_name=network, role="cpa")

    def test_container_rejects_every_host_port_publication(self) -> None:
        key = f"{r8.CPA_PORT}/tcp"
        base = {
            "HostConfig": {"PortBindings": {}, "PublishAllPorts": False},
            "NetworkSettings": {"Ports": {key: None}},
        }
        r8.verify_no_host_port_binding(base, role="cpa")
        publish_all = json.loads(json.dumps(base))
        publish_all["HostConfig"]["PublishAllPorts"] = True
        with self.assertRaisesRegex(r8.RunnerError, "enables Host port"):
            r8.verify_no_host_port_binding(publish_all, role="cpa")
        host_mutation = json.loads(json.dumps(base))
        host_mutation["HostConfig"]["PortBindings"] = {
            key: [{"HostIp": "127.0.0.1", "HostPort": "18394"}]
        }
        with self.assertRaisesRegex(r8.RunnerError, "HostConfig port"):
            r8.verify_no_host_port_binding(host_mutation, role="cpa")
        runtime_mutation = json.loads(json.dumps(base))
        runtime_mutation["NetworkSettings"]["Ports"][key] = [
            {"HostIp": "127.0.0.1", "HostPort": "18394"}
        ]
        with self.assertRaisesRegex(r8.RunnerError, "runtime Host port"):
            r8.verify_no_host_port_binding(runtime_mutation, role="cpa")

    def test_internal_network_contract_is_bridge_local_ipv4_and_identity_closed(self) -> None:
        lane = object.__new__(r8.Lane)
        lane.lane = "primary"
        lane.execution_id = str(uuid.uuid4())
        lane.network = "cag-r9-primary-test-net"
        lane.mock_container = "cag-r9-primary-test-mock"
        lane.cpa_container = "cag-r9-primary-test-cpa"
        lane.mock_container_id = "1" * 64
        lane.cpa_container_id = "2" * 64
        network = {
            "Driver": "bridge",
            "Scope": "local",
            "Internal": True,
            "EnableIPv6": False,
            "Attachable": False,
            "Ingress": False,
            "Labels": {
                "cag.round9.execution": lane.execution_id,
                "cag.round9.lane": lane.lane,
            },
            "IPAM": {"Config": [{"Subnet": "172.19.0.0/16", "Gateway": "172.19.0.1"}]},
            "Containers": {
                lane.mock_container_id: {
                    "Name": lane.mock_container,
                    "IPv4Address": "172.19.0.2/16",
                    "IPv6Address": "",
                },
                lane.cpa_container_id: {
                    "Name": lane.cpa_container,
                    "IPv4Address": "172.19.0.3/16",
                    "IPv6Address": "",
                },
            },
        }

        def check(value: dict[str, object]) -> None:
            result = subprocess.CompletedProcess(
                ["docker", "network", "inspect"],
                0,
                r8.canonical_bytes([value]),
                b"",
            )
            with mock.patch.object(r8, "docker", return_value=result):
                lane.verify_internal_network(
                    {
                        lane.mock_container: "172.19.0.2",
                        lane.cpa_container: "172.19.0.3",
                    }
                )

        check(network)
        multicast_address = str(ipaddress.IPv4Address((224 << 24) | 1))
        mutations = {
            "driver": lambda value: value.update(Driver="overlay"),
            "scope": lambda value: value.update(Scope="swarm"),
            "internal": lambda value: value.update(Internal=False),
            "ipv6": lambda value: value.update(EnableIPv6=True),
            "attachable": lambda value: value.update(Attachable=True),
            "label": lambda value: value["Labels"].update({"cag.round9.lane": "other"}),
            "non-rfc1918-subnet": lambda value: value["IPAM"]["Config"][0].update(
                Subnet="192.0.2.0/24"
            ),
            "missing-gateway": lambda value: value["IPAM"]["Config"][0].pop("Gateway"),
            "non-rfc1918-gateway": lambda value: value["IPAM"]["Config"][0].update(
                Gateway="192.0.2.1"
            ),
            "outside-subnet-gateway": lambda value: value["IPAM"]["Config"][0].update(
                Gateway="172.20.0.1"
            ),
            "network-gateway": lambda value: value["IPAM"]["Config"][0].update(
                Gateway="172.19.0.0"
            ),
            "broadcast-gateway": lambda value: value["IPAM"]["Config"][0].update(
                Gateway="172.19.255.255"
            ),
            "unspecified-gateway": lambda value: value["IPAM"]["Config"][0].update(
                Gateway="0.0.0.0"
            ),
            "multicast-gateway": lambda value: value["IPAM"]["Config"][0].update(
                Gateway=multicast_address
            ),
            "identity": lambda value: value["Containers"].update(
                {"3" * 64: value["Containers"].pop(lane.cpa_container_id)}
            ),
            "duplicate-ip": lambda value: value["Containers"][lane.cpa_container_id].update(
                IPv4Address="172.19.0.2/16"
            ),
            "container-network": lambda value: value["Containers"][
                lane.cpa_container_id
            ].update(IPv4Address="172.19.0.0/16"),
            "container-broadcast": lambda value: value["Containers"][
                lane.cpa_container_id
            ].update(IPv4Address="172.19.255.255/16"),
            "container-unspecified": lambda value: value["Containers"][
                lane.cpa_container_id
            ].update(IPv4Address="0.0.0.0/16"),
            "container-multicast": lambda value: value["Containers"][
                lane.cpa_container_id
            ].update(IPv4Address=multicast_address + "/16"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                drift = json.loads(json.dumps(network))
                mutate(drift)
                with self.assertRaises(r8.RunnerError):
                    check(drift)

    def test_stream_and_nonstream_response_contracts_require_termination_markers(self) -> None:
        chat = r8.canonical_bytes(
            {
                "id": "chatcmpl-round9",
                "object": "chat.completion",
                "created": 0,
                "model": r8.MODEL_NAME,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        )
        responses = r8.canonical_bytes(
            {
                "id": "resp_round9",
                "object": "response",
                "status": "completed",
                "model": r8.MODEL_NAME,
                "output": [
                    {
                        "type": "message",
                        "status": "completed",
                        "content": [{"type": "output_text", "text": "ok"}],
                    }
                ],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            }
        )
        chat_stream = (
            b'data: {"object":"chat.completion.chunk","model":"round9-test-model","choices":[{"finish_reason":null}]}\n\n'
            b'data: {"object":"chat.completion.chunk","model":"round9-test-model","choices":[{"finish_reason":"stop"}]}\n\n'
            b"data: [DONE]\n\n"
        )
        response_id = "resp_round9"
        item_id = "msg_resp_round9_0"
        in_progress_response = {
            "id": response_id,
            "object": "response",
            "status": "in_progress",
            "model": r8.MODEL_NAME,
            "output": [],
        }
        completed_item = {
            "id": item_id,
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "ok"}],
        }
        stream_payloads = [
            {"response": in_progress_response},
            {"response": dict(in_progress_response)},
            {
                "output_index": 0,
                "item": {
                    "id": item_id,
                    "type": "message",
                    "status": "in_progress",
                    "role": "assistant",
                    "content": [],
                },
            },
            {
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": ""},
            },
            {
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "delta": "ok",
            },
            {
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "text": "ok",
            },
            {
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": "ok"},
            },
            {"output_index": 0, "item": completed_item},
            {
                "response": {
                    "id": response_id,
                    "object": "response",
                    "status": "completed",
                    "model": r8.MODEL_NAME,
                    "output": [completed_item],
                }
            },
        ]
        stream_events = [
            "response.created",
            "response.in_progress",
            "response.output_item.added",
            "response.content_part.added",
            "response.output_text.delta",
            "response.output_text.done",
            "response.content_part.done",
            "response.output_item.done",
            "response.completed",
        ]
        responses_stream = b""
        for sequence, (event, payload) in enumerate(
            zip(stream_events, stream_payloads, strict=True), start=1
        ):
            payload = {"type": event, "sequence_number": sequence, **payload}
            responses_stream += (
                b"event: "
                + event.encode("ascii")
                + b"\ndata: "
                + r8.canonical_bytes(payload)
                + b"\n\n"
            )
        responses_stream += b"\n"
        self.assertEqual(r8.validate_upstream_response("chat", False, chat), (True, True))
        self.assertEqual(
            r8.validate_upstream_response("responses", False, responses), (True, True)
        )
        self.assertEqual(
            r8.validate_upstream_response("chat", True, chat_stream), (True, True)
        )
        self.assertEqual(
            r8.validate_upstream_response("responses", True, responses_stream),
            (True, True),
        )
        with self.assertRaises(r8.RunnerError):
            r8.validate_upstream_response("chat", True, chat_stream.replace(b"[DONE]", b"{}"))
        for chat_drift in (chat_stream + b"\n", chat_stream + b"\n\n"):
            with self.assertRaises(r8.RunnerError):
                r8.validate_upstream_response("chat", True, chat_drift)
        for label, drift in {
            "responses-double-lf": responses_stream[:-1],
            "responses-four-lf": responses_stream + b"\n",
            "responses-id-field": responses_stream.replace(
                b"event: response.created\n", b"event: response.created\nid: forbidden\n", 1
            ),
            "responses-retry-field": responses_stream.replace(
                b"event: response.created\n", b"event: response.created\nretry: 1\n", 1
            ),
            "responses-comment": responses_stream.replace(
                b"event: response.created\n", b"event: response.created\n: forbidden\n", 1
            ),
            "responses-sequence-string": responses_stream.replace(
                b'"sequence_number":1', b'"sequence_number":"1"', 1
            ),
            "responses-event-order": responses_stream.replace(
                b"event: response.created", b"event: response.in_progress", 1
            ),
            "responses-old-three-event": (
                b"event: response.created\ndata: {}\n\n"
                b'event: response.output_text.delta\ndata: {"type":"response.output_text.delta"}\n\n'
                b"event: response.completed\ndata: {}\n\n\n"
            ),
        }.items():
            with self.subTest(label=label), self.assertRaises(r8.RunnerError):
                r8.validate_upstream_response("responses", True, drift)

    @unittest.skipUnless(hasattr(os, "getuid"), "requires POSIX uid/gid")
    def test_container_args_apply_cpu_memory_and_bounded_local_logs(self) -> None:
        lane = object.__new__(r8.Lane)
        lane.network = "cag-r9-test-net"
        lane.execution_id = str(uuid.uuid4())
        lane.lane = "primary"
        args = lane.common_container_args("mock", "cag-r9-test-mock")
        joined = "\n".join(args)
        self.assertIn("--cpus\n0.5", joined)
        self.assertIn(f"--memory\n{128 * 1024 * 1024}", joined)
        self.assertIn(f"--memory-swap\n{128 * 1024 * 1024}", joined)
        self.assertIn("--log-driver\nlocal", joined)
        self.assertIn("--log-opt\nmax-size=8m", joined)
        self.assertIn("--log-opt\nmax-file=1", joined)
        self.assertIn("--log-opt\ncompress=false", joined)

    def test_cleanup_distinguishes_not_found_from_daemon_failure(self) -> None:
        execution_id = str(uuid.uuid4())
        resources = r8.DockerResources("cag-r9-primary-test", execution_id)
        name = "cag-r9-primary-test-cpa"
        resources.add_container(name)

        def missing(args: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            if args == ["inspect", name]:
                return subprocess.CompletedProcess(args, 1, b"", b"No such container")
            if args[:2] == ["container", "ls"]:
                return subprocess.CompletedProcess(args, 0, b"", b"")
            raise AssertionError(args)

        with mock.patch.object(r8, "docker", side_effect=missing):
            resources.cleanup()

        def daemon_error(args: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            if args == ["inspect", name]:
                return subprocess.CompletedProcess(args, 1, b"", b"daemon unavailable")
            if args[:2] == ["container", "ls"]:
                return subprocess.CompletedProcess(args, 1, b"", b"daemon unavailable")
            raise AssertionError(args)

        with mock.patch.object(r8, "docker", side_effect=daemon_error):
            with self.assertRaises(r8.RunnerError):
                resources.cleanup()

    def test_cleanup_requires_confirmed_absence_after_remove(self) -> None:
        execution_id = str(uuid.uuid4())
        resources = r8.DockerResources("cag-r9-primary-test", execution_id)
        name = "cag-r9-primary-test-cpa"
        resources.add_container(name)
        inspect_payload = r8.canonical_bytes(
            [{"Config": {"Labels": {"cag.round9.execution": execution_id}}}]
        )

        def still_present(args: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            if args == ["inspect", name]:
                return subprocess.CompletedProcess(args, 0, inspect_payload, b"")
            if args == ["rm", "--force", name]:
                return subprocess.CompletedProcess(args, 1, b"", b"daemon timeout")
            if args[:2] == ["container", "ls"]:
                return subprocess.CompletedProcess(args, 0, f"{name}\n".encode(), b"")
            raise AssertionError(args)

        with mock.patch.object(r8, "docker", side_effect=still_present):
            with self.assertRaises(r8.RunnerError):
                resources.cleanup()

    @unittest.skipUnless(hasattr(os, "getuid"), "requires POSIX uid/gid")
    def test_lane_registers_resources_before_create_or_run(self) -> None:
        events: list[tuple[str, str]] = []

        class TrackingResources:
            def add_network(self, name: str) -> None:
                events.append(("register-network", name))

            def add_container(self, name: str) -> None:
                events.append(("register-container", name))

        lane = object.__new__(r8.Lane)
        lane.lane = "primary"
        lane.execution_id = str(uuid.uuid4())
        lane.network = "cag-r9-primary-test-net"
        lane.mock_container = "cag-r9-primary-test-mock"
        lane.cpa_container = "cag-r9-primary-test-cpa"
        lane.mock_image_id = "sha256:" + "a" * 64
        lane.cpa_image_id = "sha256:" + "b" * 64
        lane.release_commit = COMMIT
        lane.release_tree = TREE
        lane.resources = TrackingResources()
        lane.plugin_dir = self.root / "plugins"
        lane.config_dir = self.root / "config"
        lane.auth_dir = self.root / "auth"
        lane.audit_dir = self.root / "audit"
        lane.secret_dir = self.root / "secrets"
        lane.record = lambda *args, **kwargs: None
        lane.mock_total = lambda: 0
        lane.wait_plugin = lambda *args, **kwargs: None
        lane.verify_container_security = lambda *args, **kwargs: None
        lane.verify_internal_network = lambda *args, **kwargs: None
        lane.verify_request_logging_controls = lambda: None

        def record_docker(args: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            if args[:2] == ["network", "create"]:
                self.assertIn(("register-network", lane.network), events)
                events.append(("docker-network", lane.network))
            elif args and args[0] == "run":
                name = args[args.index("--name") + 1]
                self.assertIn(("register-container", name), events)
                self.assertNotIn("--publish", args)
                events.append(("docker-run", name))
            return subprocess.CompletedProcess(args, 0, b"", b"")

        def fake_http_json(_: str, method: str, path: str, **__: object) -> object:
            if method == "GET" and path == "/healthz":
                return {
                    "contract": r8.MOCK_CONTRACT,
                    "healthy": True,
                    "request_body_retention": False,
                }
            if method == "POST" and path == "/__cag/reset":
                return {"total": 0}
            raise AssertionError((method, path))

        inspect_payloads = [
            {
                "Id": "1" * 64,
                "NetworkSettings": {
                    "Networks": {lane.network: {"IPAddress": "172.19.0.2"}}
                }
            },
            {
                "Id": "2" * 64,
                "NetworkSettings": {
                    "Networks": {lane.network: {"IPAddress": "172.19.0.3"}}
                }
            },
        ]
        with mock.patch.object(r8, "docker", side_effect=record_docker), mock.patch.object(
            r8, "docker_inspect_one", side_effect=inspect_payloads
        ), mock.patch.object(r8, "http_json", side_effect=fake_http_json):
            lane.create_network()
            lane.start_mock()
            lane.start_cpa()

        self.assertLess(
            events.index(("register-network", lane.network)),
            events.index(("docker-network", lane.network)),
        )
        for name in (lane.mock_container, lane.cpa_container):
            self.assertLess(
                events.index(("register-container", name)),
                events.index(("docker-run", name)),
            )

    def test_store_so_installs_only_at_linux_amd64_platform_path(self) -> None:
        work = self.root / "lane-work"
        lane = r8.Lane(
            lane="primary",
            version=r8.PRIMARY_VERSION,
            cpa_commit=r8.PRIMARY_COMMIT,
            cpa_image="local/cpa:pinned",
            cpa_image_id="sha256:" + "a" * 64,
            cpa_build_date="2026-01-02T03:04:05Z",
            mock_image="local/mock:pinned",
            mock_image_id="sha256:" + "b" * 64,
            artifacts=self.artifacts,
            work=work,
            release_commit=COMMIT,
            release_tree=TREE,
            so_sha=digest(self.artifacts / r8.SO_NAME),
            fixtures=fixture_document()["pairs"],  # type: ignore[arg-type]
            execution_id=str(uuid.uuid4()),
        )
        lane.prepare_files()
        installed = lane.plugin_dir / "linux" / "amd64" / r8.SO_NAME
        self.assertTrue(installed.is_file())
        self.assertFalse((lane.plugin_dir / r8.SO_NAME).exists())
        if os.name == "posix":
            self.assertEqual((lane.secret_dir / "hmac.key").stat().st_mode & 0o777, 0o600)
        config_text = (lane.config_dir / "config.yaml").read_text(encoding="utf-8")
        self.assertIn("commercial-mode: true\n", config_text)
        self.assertIn("request-log: false\n", config_text)
        self.assertIn("logging-to-file: false\n", config_text)
        lane.transcript.close()
        for path in lane.directory.rglob("*"):
            if path.is_file():
                path.chmod(0o700)
        lane.cleanup_sensitive_work()

    def test_plugin_config_and_ready_status_separate_window_and_total_limits(self) -> None:
        lane = object.__new__(r8.Lane)
        lane.release_commit = COMMIT
        lane.total_text_limit_bytes = r8.TOTAL_TEXT_LIMIT_BYTES
        config = lane.plugin_config("balanced", True)
        self.assertEqual(config["max_scan_bytes"], r8.SCAN_LIMIT_BYTES)
        self.assertEqual(config["max_total_text_bytes"], r8.TOTAL_TEXT_LIMIT_BYTES)
        self.assertIs(config["audit"]["require_persistent_storage"], True)
        plugins = {
            "plugins_enabled": True,
            "plugins": [
                {
                    "id": "cyber-abuse-guard",
                    "registered": True,
                    "configured": True,
                    "effective_enabled": True,
                }
            ],
        }
        status = {
            "id": "cyber-abuse-guard",
            "version": r8.ARTIFACT_VERSION,
            "commit": COMMIT,
            "dirty": False,
            "loaded": True,
            "initialized": True,
            "enforcement_ready": True,
            "enabled": True,
            "mode": "balanced",
            "priority": 300,
            "ruleset_version_match": True,
            "audit_degraded": False,
            "hmac_stable": True,
            "hmac_degraded": False,
            "persistence_degraded": False,
            "last_reconfigure_error": "",
            "last_config_error": "",
            "ruleset_sha256": "a" * 64,
            "classifier_policy_sha256": "b" * 64,
            "effective_limits": {
                "max_text_window_bytes": r8.SCAN_LIMIT_BYTES,
                "max_total_text_bytes": r8.TOTAL_TEXT_LIMIT_BYTES,
                "legacy_max_scan_bytes_configured": r8.SCAN_LIMIT_BYTES,
            },
            "audit": {
                "enabled": True,
                "healthy": True,
                "degraded": False,
                "schema_version": 6,
                "persistence_expected": True,
                "persistence_verified": True,
            },
            "raw_capture": {
                "enabled": True,
                "only_blocked": True,
                "redact_secrets": True,
                "ttl_hours": 1,
            },
        }
        lane.assert_plugin_ready(plugins, status, "balanced", True)
        status["effective_limits"]["max_total_text_bytes"] = r8.SCAN_LIMIT_BYTES
        with self.assertRaises(r8.RunnerError):
            lane.assert_plugin_ready(plugins, status, "balanced", True)

    def test_request_logging_controls_require_exact_booleans_and_empty_auth(self) -> None:
        lane = object.__new__(r8.Lane)
        lane.cpa_url = "http://172.19.0.3:8317"
        lane.management_key = "test-management-key"
        lane.auth_dir = self.root / "logging-auth"
        lane.auth_dir.mkdir()
        safe = {
            "commercial-mode": True,
            "request-log": False,
            "logging-to-file": False,
        }
        with mock.patch.object(r8, "http_json", return_value=safe):
            lane.verify_request_logging_controls()
        for key, value in (
            ("commercial-mode", False),
            ("commercial-mode", "true"),
            ("request-log", True),
            ("logging-to-file", True),
        ):
            with self.subTest(key=key, value=value):
                unsafe = dict(safe)
                unsafe[key] = value
                with mock.patch.object(r8, "http_json", return_value=unsafe):
                    with self.assertRaises(r8.RunnerError):
                        lane.verify_request_logging_controls()
        missing = dict(safe)
        del missing["commercial-mode"]
        with mock.patch.object(r8, "http_json", return_value=missing):
            with self.assertRaises(r8.RunnerError):
                lane.verify_request_logging_controls()
        logs = lane.auth_dir / "logs"
        logs.mkdir()
        (logs / "error-v1-chat-completions-fixture.log").write_text(
            "synthetic fixture", encoding="utf-8"
        )
        with mock.patch.object(r8, "http_json", return_value=safe):
            with self.assertRaisesRegex(r8.RunnerError, "auth directory must remain empty"):
                lane.verify_request_logging_controls()

    def test_assembler_refuses_existing_output(self) -> None:
        output = self.root / "occupied"
        output.mkdir()
        (output / "round9-host-evidence.json").write_text("stale", encoding="utf-8")
        with self.assertRaises(r8.RunnerError):
            r8.verify_artifact_and_assemble(
                self.artifacts, self.primary, output, COMMIT, TREE, self.execution
            )

    def test_assembler_concurrent_placeholder_is_never_overwritten(self) -> None:
        output = self.root / "concurrent-placeholder"
        placeholder = output / "round9-host-evidence.json"
        real_link = os.link
        injected = False

        def occupy_before_link(source: str, target: str, **kwargs: object) -> None:
            nonlocal injected
            if not injected:
                injected = True
                placeholder.write_bytes(b"concurrent-owner")
            real_link(source, target, **kwargs)

        with mock.patch.object(r8.os, "link", side_effect=occupy_before_link):
            with self.assertRaises(r8.RunnerError):
                r8.verify_artifact_and_assemble(
                    self.artifacts,
                    self.primary,
                    output,
                    COMMIT,
                    TREE,
                    self.execution,
                )

        self.assertTrue(injected)
        self.assertEqual(placeholder.read_bytes(), b"concurrent-owner")
        self.assertFalse((output / "round9-host-evidence.json.sha256").exists())
        self.assertFalse((output / "round9-host-evidence.json.b64").exists())
        self.assertEqual(list(output.glob(".round9-host-evidence.json*.tmp")), [])

    def test_assembler_mid_publish_failure_does_not_delete_replacement(self) -> None:
        output = self.root / "mid-publish-failure"
        evidence = output / "round9-host-evidence.json"
        real_link = os.link
        calls = 0

        def fail_after_replacement(source: str, target: str, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                real_link(source, target, **kwargs)
                return
            evidence.unlink()
            evidence.write_bytes(b"concurrent-replacement")
            raise OSError(errno.EIO, "injected publication failure")

        with mock.patch.object(r8.os, "link", side_effect=fail_after_replacement):
            with self.assertRaises(r8.RunnerError):
                r8.verify_artifact_and_assemble(
                    self.artifacts,
                    self.primary,
                    output,
                    COMMIT,
                    TREE,
                    self.execution,
                )

        self.assertEqual(calls, 2)
        self.assertEqual(evidence.read_bytes(), b"concurrent-replacement")
        self.assertFalse((output / "round9-host-evidence.json.sha256").exists())
        self.assertFalse((output / "round9-host-evidence.json.b64").exists())
        self.assertEqual(list(output.glob(".round9-host-evidence.json*.tmp")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
