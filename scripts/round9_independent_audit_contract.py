#!/usr/bin/env python3
"""Verify privacy-bounded Round 9 independent-audit evidence.

This verifier consumes only signed aggregate evidence, candidate artifact bytes,
and protected Git ledger metadata.  It never accepts or opens independent corpus
prompts, responses, production data, or real-Provider material.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable
from urllib import error, parse, request


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools" / "round9-eval"))

from round9_eval_core import (  # noqa: E402
    ContractError,
    HEX40,
    HEX64,
    IDENTIFIER,
    REPOSITORY,
    SHA256_DIGEST,
    canonical_bytes,
    exact_bool,
    exact_int,
    exact_object,
    load_canonical_json,
    load_json_bytes,
    openssl_verify,
    require_literal,
    require_pattern,
    sha256_bytes,
)


TAG = "v0.16-rc.3"
SOURCE_VERSION = "0.16"
ARTIFACT_VERSION = "0.16-rc.3"
RELEASE_WORKFLOW = ".github/workflows/round9-release-rc.yml"
HOST_WORKFLOW = ".github/workflows/round9-host-validation.yml"
RELEASE_TITLE = (
    "v0.16-rc.3 - Round 9 counted-Mock candidate; independent audit required"
)
SIGNED_ENVELOPE_SCHEMA = "round9-independent-audit-signed-envelope/v1"
EVIDENCE_SCHEMA = "round9-independent-audit-evidence/v1"
LEDGER_EVENT_SCHEMA = "round9-independent-audit-ledger-event/v1"
LEDGER_PROOF_SCHEMA = "round9-independent-audit-ledger-proof/v1"
LEDGER_NAMESPACE_PREFIX = "round9-independent-audit-ledger"
PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"
ASSET_NAMES = (
    "build-metadata.json",
    "checksums.txt",
    "cyber-abuse-guard-v0.16-rc.3-audit-bundle.zip",
    "cyber-abuse-guard-v0.16-rc.3-source.tar.gz",
    "cyber-abuse-guard-v0.16-rc.3-source.tar.gz.sha256",
    "cyber-abuse-guard-v0.16-rc.3.so",
    "cyber-abuse-guard-v0.16-rc.3.so.sha256",
    "cyber-abuse-guard_0.16-rc.3_linux_amd64.zip",
    "rc-release-evidence.md",
    "rc-release-evidence.md.sha256",
    "rc-release-manifest.json",
    "rc-release-manifest.json.sha256",
    "rc-release-test-summary.txt",
    "rc-release-test-summary.txt.sha256",
    "round9-external-evaluation.json",
    "round9-external-ledger-proof.json",
    "ruleset-manifest.json",
    "ruleset.sha256",
    "sbom.cdx.json",
)
ASSET_NAME_SET = frozenset(ASSET_NAMES)
HOST_ASSET_NAMES = frozenset(
    {"round9-external-evaluation.json", "round9-external-ledger-proof.json"}
)
WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
WORKFLOW_REF = re.compile(r"^refs/(?:heads|tags)/[^\x00-\x20~^:?*\\]{1,240}$")
UTC_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class EvidenceNotProvided(ContractError):
    """Raised when the independent-audit package or trust anchor is absent."""


def fail(message: str) -> None:
    raise ContractError(message)


def require_present_file(value: str, label: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceNotProvided(f"{label} is NOT_PROVIDED")
    path = Path(value)
    if path.is_symlink() or not path.is_file():
        raise EvidenceNotProvided(f"{label} is NOT_PROVIDED")
    return path


def require_asset_directory(value: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceNotProvided("independent-audit candidate asset directory is NOT_PROVIDED")
    path = Path(value)
    if path.is_symlink() or not path.is_dir():
        raise EvidenceNotProvided("independent-audit candidate asset directory is NOT_PROVIDED")
    return path


def required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceNotProvided(f"{label} is NOT_PROVIDED")
    return value


def positive_argument(value: Any, label: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        result = value
    elif isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value):
        result = int(value)
    elif value in {None, ""}:
        raise EvidenceNotProvided(f"{label} is NOT_PROVIDED")
    else:
        fail(f"{label} must be a positive integer")
    if result < 1:
        fail(f"{label} must be a positive integer")
    return result


def regular_file_identity(
    path: Path, label: str, *, maximum: int = 67_108_864
) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ContractError(f"{label} must be a readable regular non-symlink file") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            fail(f"{label} size or file type is outside the reviewed bound")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, min(1_048_576, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                fail(f"{label} exceeds the reviewed bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            total != before.st_size
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            fail(f"{label} changed while being hashed")
        return {"bytes": total, "sha256": digest.hexdigest()}
    finally:
        os.close(descriptor)


def asset_identities(asset_dir: Path) -> dict[str, dict[str, Any]]:
    try:
        entries = list(os.scandir(asset_dir))
    except OSError as exc:
        raise ContractError("candidate asset directory cannot be enumerated") from exc
    names = [entry.name for entry in entries]
    if (
        len(names) != len(ASSET_NAMES)
        or len(names) != len(set(names))
        or frozenset(names) != ASSET_NAME_SET
    ):
        fail("independent-audit candidate asset allowlist differs from the exact 19 assets")
    identities: dict[str, dict[str, Any]] = {}
    for name in ASSET_NAMES:
        identities[name] = regular_file_identity(
            asset_dir / name, f"candidate asset {name}"
        )
    return identities


def challenge_sha256(challenge: str) -> str:
    require_pattern(challenge, HEX64, "independent-audit challenge")
    return hashlib.sha256(bytes.fromhex(challenge)).hexdigest()


def ledger_namespace(commit: str, challenge_digest: str) -> str:
    require_pattern(commit, HEX40, "ledger candidate commit")
    require_pattern(challenge_digest, HEX64, "ledger challenge sha256")
    return f"{LEDGER_NAMESPACE_PREFIX}/{commit}/{challenge_digest}"


def ledger_ref(namespace: str, event: str) -> str:
    if not namespace.startswith(LEDGER_NAMESPACE_PREFIX + "/"):
        fail("independent-audit ledger namespace is outside the reviewed prefix")
    if event not in {"reserved", "started", "result", "aborted"}:
        fail("unsupported independent-audit ledger event")
    return f"refs/tags/{namespace}/{event}"


def verify_signed_envelope(
    envelope: Any,
    public_key: Path,
    expected_key_id: str,
    *,
    expected_payload_schema: str,
    openssl: str = "openssl",
) -> dict[str, Any]:
    value = exact_object(
        envelope, {"schema", "payload", "signature"}, "independent-audit signed envelope"
    )
    require_literal(
        value["schema"], SIGNED_ENVELOPE_SCHEMA, "independent-audit signed envelope schema"
    )
    signature = exact_object(
        value["signature"],
        {"algorithm", "key_id", "value_base64"},
        "independent-audit signature",
    )
    require_literal(signature["algorithm"], "ed25519", "independent-audit signature algorithm")
    require_literal(signature["key_id"], expected_key_id, "independent-audit signature key id")
    encoded = signature["value_base64"]
    if not isinstance(encoded, str):
        fail("independent-audit signature value must be base64 text")
    try:
        raw_signature = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ContractError("independent-audit signature is not canonical base64") from exc
    if base64.b64encode(raw_signature).decode("ascii") != encoded:
        fail("independent-audit signature is not canonical base64")
    payload = value["payload"]
    if not isinstance(payload, dict):
        fail("independent-audit signed payload must be an object")
    require_literal(payload.get("schema"), expected_payload_schema, "independent-audit payload schema")
    openssl_verify(canonical_bytes(payload), raw_signature, public_key, openssl)
    return payload


def nested_object(value: Any, key: str, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get(key), dict):
        fail(f"{label} must be an object")
    return value[key]


def validate_manifest(
    manifest: Any,
    assets: dict[str, dict[str, Any]],
    args: argparse.Namespace,
) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        fail("Round 9 publication manifest must be an object")
    expected_workflow_ref = (
        f"{args.repository}/{RELEASE_WORKFLOW}@refs/tags/{args.tag}"
    )
    scalar_expectations = {
        "schema_version": 6,
        "release_phase": "publish",
        "publish_rc_release": True,
        "source_version": SOURCE_VERSION,
        "artifact_version": ARTIFACT_VERSION,
        "tag": args.tag,
        "tag_object": args.tag_object_sha,
        "commit": args.commit,
        "tree": args.tree,
        "artifact_count": len(ASSET_NAMES),
    }
    for key, expected in scalar_expectations.items():
        if manifest.get(key) != expected:
            fail(f"Round 9 publication manifest identity differs at {key}")
    workflow = nested_object(manifest, "workflow", "Round 9 publication manifest workflow")
    if (
        workflow.get("repository") != args.repository
        or workflow.get("ref") != expected_workflow_ref
        or workflow.get("sha") != args.commit
        or workflow.get("dispatch_ref") != f"refs/tags/{args.tag}"
    ):
        fail("Round 9 publication manifest workflow identity differs")
    round9 = nested_object(manifest, "round9", "Round 9 publication manifest round9")
    if round9.get("release_lane") != "round9":
        fail("Round 9 publication manifest release lane differs")
    classifier = nested_object(round9, "classifier", "Round 9 classifier identity")
    ruleset = nested_object(round9, "ruleset", "Round 9 ruleset identity")
    if set(classifier) != {"version", "sha256"} or set(ruleset) != {"version", "sha256"}:
        fail("Round 9 classifier or ruleset identity keys differ")
    require_pattern(classifier.get("version"), IDENTIFIER, "classifier policy version")
    require_pattern(classifier.get("sha256"), HEX64, "classifier policy sha256")
    require_pattern(ruleset.get("version"), IDENTIFIER, "ruleset version")
    require_pattern(ruleset.get("sha256"), HEX64, "ruleset sha256")
    release = nested_object(round9, "release", "Round 9 release identity")
    if (
        release.get("tag") != args.tag
        or release.get("title") != RELEASE_TITLE
        or release.get("publication_permitted") is not True
        or release.get("draft") is not False
        or release.get("prerelease") is not True
        or release.get("latest") is not False
    ):
        fail("Round 9 release identity differs")
    body = release.get("body")
    if not isinstance(body, str) or not all(
        marker in body for marker in ("Public adversarial v11", "latest=false", "independent audit")
    ):
        fail("Round 9 release body does not retain the reviewed claim boundary")
    allowlist = release.get("asset_allowlist")
    if (
        not isinstance(allowlist, list)
        or len(allowlist) != len(ASSET_NAMES)
        or len(set(allowlist)) != len(allowlist)
        or frozenset(allowlist) != ASSET_NAME_SET
    ):
        fail("Round 9 publication manifest asset allowlist differs")
    if manifest.get("independent_audit") != "NOT_PROVIDED" or manifest.get(
        "independent_audit_requirement"
    ) != "required":
        fail("pre-audit publication manifest must not self-assert independent approval")
    artifact_manifest = nested_object(manifest, "artifacts", "Round 9 artifact manifest")
    so = nested_object(artifact_manifest, "so", "Round 9 SO artifact")
    external_evaluation = nested_object(
        artifact_manifest, "external_evaluation", "Round 9 external evaluation artifact"
    )
    external_ledger = nested_object(
        artifact_manifest, "external_ledger_proof", "Round 9 external ledger artifact"
    )
    expected_artifact_hashes = {
        "so": (
            so.get("name"),
            so.get("sha256"),
            "cyber-abuse-guard-v0.16-rc.3.so",
        ),
        "external evaluation": (
            external_evaluation.get("name"),
            external_evaluation.get("sha256"),
            "round9-external-evaluation.json",
        ),
        "external ledger proof": (
            external_ledger.get("name"),
            external_ledger.get("sha256"),
            "round9-external-ledger-proof.json",
        ),
    }
    for label, (name, digest, expected_name) in expected_artifact_hashes.items():
        if name != expected_name or digest != assets[expected_name]["sha256"]:
            fail(f"Round 9 {label} artifact identity differs")
    for key, name in (
        ("build_metadata_sha256", "build-metadata.json"),
        ("ruleset_manifest_sha256", "ruleset-manifest.json"),
    ):
        if artifact_manifest.get(key) != assets[name]["sha256"]:
            fail(f"Round 9 artifact manifest differs at {key}")
    return manifest


def validate_candidate(
    value: Any,
    manifest: dict[str, Any],
    assets: dict[str, dict[str, Any]],
    manifest_identity: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    candidate = exact_object(
        value,
        {
            "repository",
            "tag",
            "tag_object_sha",
            "source_version",
            "artifact_version",
            "commit",
            "tree",
            "release_manifest_bytes",
            "release_manifest_sha256",
            "so_sha256",
            "build_metadata_sha256",
            "ruleset_manifest_sha256",
            "classifier_policy_version",
            "classifier_policy_sha256",
            "ruleset_version",
            "ruleset_sha256",
            "external_evaluation_sha256",
            "external_ledger_proof_sha256",
        },
        "independent-audit candidate",
    )
    expected = {
        "repository": args.repository,
        "tag": args.tag,
        "tag_object_sha": args.tag_object_sha,
        "source_version": SOURCE_VERSION,
        "artifact_version": ARTIFACT_VERSION,
        "commit": args.commit,
        "tree": args.tree,
        "release_manifest_bytes": manifest_identity["bytes"],
        "release_manifest_sha256": manifest_identity["sha256"],
        "so_sha256": assets["cyber-abuse-guard-v0.16-rc.3.so"]["sha256"],
        "build_metadata_sha256": assets["build-metadata.json"]["sha256"],
        "ruleset_manifest_sha256": assets["ruleset-manifest.json"]["sha256"],
        "classifier_policy_version": manifest["round9"]["classifier"]["version"],
        "classifier_policy_sha256": manifest["round9"]["classifier"]["sha256"],
        "ruleset_version": manifest["round9"]["ruleset"]["version"],
        "ruleset_sha256": manifest["round9"]["ruleset"]["sha256"],
        "external_evaluation_sha256": assets["round9-external-evaluation.json"][
            "sha256"
        ],
        "external_ledger_proof_sha256": assets[
            "round9-external-ledger-proof.json"
        ]["sha256"],
    }
    if candidate != expected:
        fail("independent-audit candidate identity differs from the exact 19 assets")
    return candidate


def validate_audit_identity(
    value: Any, args: argparse.Namespace, public_key_sha256: str
) -> dict[str, Any]:
    audit = exact_object(
        value,
        {
            "auditor_id",
            "auditor_repository",
            "workflow_name",
            "workflow_path",
            "workflow_ref",
            "workflow_sha",
            "run_id",
            "run_attempt",
            "key_id",
            "public_key_sha256",
            "challenge_sha256",
            "independent_from_candidate_builder",
            "independent_from_host_evaluator",
            "restricted_material_zero_access_claim",
            "production_accessed",
            "real_provider_contacted",
        },
        "independent-audit identity",
    )
    require_pattern(audit["auditor_id"], IDENTIFIER, "independent auditor id")
    require_pattern(audit["auditor_repository"], REPOSITORY, "independent auditor repository")
    require_pattern(audit["workflow_path"], WORKFLOW_PATH, "independent auditor workflow path")
    require_pattern(audit["workflow_ref"], WORKFLOW_REF, "independent auditor workflow ref")
    require_pattern(audit["workflow_sha"], HEX40, "independent auditor workflow sha")
    require_pattern(audit["key_id"], IDENTIFIER, "independent auditor key id")
    require_pattern(audit["public_key_sha256"], HEX64, "independent auditor public key sha256")
    require_pattern(audit["challenge_sha256"], HEX64, "independent audit challenge sha256")
    if not isinstance(audit["workflow_name"], str) or not 3 <= len(audit["workflow_name"]) <= 128:
        fail("independent auditor workflow name is invalid")
    exact_int(audit["run_id"], "independent auditor run id", minimum=1)
    exact_int(audit["run_attempt"], "independent auditor run attempt", minimum=1)
    expected = {
        "auditor_repository": args.auditor_repository,
        "workflow_name": args.auditor_workflow_name,
        "workflow_path": args.auditor_workflow,
        "workflow_ref": args.auditor_ref,
        "workflow_sha": args.auditor_workflow_sha,
        "run_id": args.auditor_run_id,
        "run_attempt": args.auditor_run_attempt,
        "key_id": args.key_id,
        "public_key_sha256": public_key_sha256,
        "challenge_sha256": challenge_sha256(args.challenge),
    }
    for key, expected_value in expected.items():
        if audit.get(key) != expected_value:
            fail(f"independent-audit signer/run identity differs at {key}")
    if (
        audit["auditor_repository"] == args.repository
        and audit["workflow_path"] in {RELEASE_WORKFLOW, HOST_WORKFLOW}
    ):
        fail("independent-audit signer workflow is not independent")
    exact_bool(
        audit["independent_from_candidate_builder"],
        True,
        "independence from candidate builder",
    )
    exact_bool(
        audit["independent_from_host_evaluator"],
        True,
        "independence from Host evaluator",
    )
    exact_bool(
        audit["restricted_material_zero_access_claim"],
        False,
        "restricted material zero-access claim",
    )
    exact_bool(audit["production_accessed"], False, "production access")
    exact_bool(audit["real_provider_contacted"], False, "real Provider contact")
    return audit


def validate_asset_records(
    value: Any,
    assets: dict[str, dict[str, Any]],
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(ASSET_NAMES):
        fail("independent-audit asset records must contain exactly 19 entries")
    names: list[str] = []
    records: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        record = exact_object(
            item,
            {"name", "bytes", "sha256", "provenance"},
            f"independent-audit asset record {index}",
        )
        name = record["name"]
        if not isinstance(name, str) or name not in ASSET_NAME_SET:
            fail(f"independent-audit asset record {index} has an unknown name")
        names.append(name)
        if record["bytes"] != assets[name]["bytes"] or record["sha256"] != assets[name]["sha256"]:
            fail(f"independent-audit asset bytes or SHA-256 differs for {name}")
        provenance = exact_object(
            record["provenance"],
            {
                "state",
                "predicate_type",
                "signer_repository",
                "signer_workflow",
                "signer_digest",
                "source_ref",
                "source_digest",
            },
            f"independent-audit asset provenance {name}",
        )
        expected_workflow = HOST_WORKFLOW if name in HOST_ASSET_NAMES else RELEASE_WORKFLOW
        expected_provenance = {
            "state": "VERIFIED",
            "predicate_type": PROVENANCE_PREDICATE,
            "signer_repository": args.repository,
            "signer_workflow": expected_workflow,
            "signer_digest": args.commit,
            "source_ref": f"refs/tags/{args.tag}",
            "source_digest": args.commit,
        }
        if provenance != expected_provenance:
            fail(f"independent-audit asset attestation identity differs for {name}")
        records.append(record)
    if tuple(names) != ASSET_NAMES:
        fail("independent-audit asset records are not the exact sorted 19-name allowlist")
    return records


def validate_findings(
    value: Any,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    findings = exact_object(
        value,
        {
            "decision",
            "scope",
            "source_review",
            "artifact_review",
            "external_evaluation_review",
            "release_contract_review",
        },
        "independent-audit findings",
    )
    require_literal(findings["decision"], "PASS", "independent-audit decision")
    if findings["scope"] != [
        "source",
        "artifacts",
        "supply_chain",
        "external_evaluation",
        "release_contract",
    ]:
        fail("independent-audit review scope differs")
    source_review = exact_object(
        findings["source_review"],
        {"state", "open_critical", "open_high"},
        "independent-audit source review",
    )
    if source_review != {"state": "PASS", "open_critical": 0, "open_high": 0}:
        fail("independent-audit source review is not release-admissible")
    artifact_review = exact_object(
        findings["artifact_review"],
        {"state", "assets_verified", "attestations_verified"},
        "independent-audit artifact review",
    )
    if artifact_review != {
        "state": "PASS",
        "assets_verified": len(ASSET_NAMES),
        "attestations_verified": len(ASSET_NAMES),
    }:
        fail("independent-audit artifact review is incomplete")
    external_review = exact_object(
        findings["external_evaluation_review"],
        {"state", "evaluation_sha256", "ledger_proof_sha256"},
        "independent-audit external evaluation review",
    )
    if external_review != {
        "state": "PASS",
        "evaluation_sha256": candidate["external_evaluation_sha256"],
        "ledger_proof_sha256": candidate["external_ledger_proof_sha256"],
    }:
        fail("independent-audit external evaluation review identity differs")
    release_review = exact_object(
        findings["release_contract_review"],
        {"state", "manifest_sha256", "asset_allowlist_sha256"},
        "independent-audit release contract review",
    )
    if release_review != {
        "state": "PASS",
        "manifest_sha256": candidate["release_manifest_sha256"],
        "asset_allowlist_sha256": sha256_bytes(canonical_bytes(list(ASSET_NAMES))),
    }:
        fail("independent-audit release contract review identity differs")
    return findings


def validate_privacy(value: Any) -> dict[str, Any]:
    privacy = exact_object(
        value,
        {
            "raw_prompts_in_result",
            "raw_responses_in_result",
            "request_bodies_in_result",
            "restricted_material_in_result",
            "production_data_in_result",
        },
        "independent-audit privacy boundary",
    )
    for key in privacy:
        exact_bool(privacy[key], False, f"independent-audit privacy field {key}")
    return privacy


def validate_ledger_binding(
    value: Any,
    args: argparse.Namespace,
    audit: dict[str, Any],
) -> dict[str, Any]:
    ledger = exact_object(
        value,
        {
            "repository",
            "namespace",
            "ruleset_id",
            "ruleset_name",
            "reserved_ref",
            "started_ref",
            "result_ref",
        },
        "independent-audit ledger binding",
    )
    expected_namespace = ledger_namespace(args.commit, audit["challenge_sha256"])
    if ledger["repository"] != args.repository:
        fail("independent-audit ledger repository must be the exact candidate repository")
    require_literal(ledger["namespace"], expected_namespace, "independent-audit ledger namespace")
    if ledger["ruleset_id"] != args.ledger_ruleset_id or ledger["ruleset_name"] != args.ledger_ruleset_name:
        fail("independent-audit ledger ruleset identity differs")
    for event in ("reserved", "started", "result"):
        require_literal(
            ledger[f"{event}_ref"],
            ledger_ref(expected_namespace, event),
            f"independent-audit ledger {event} ref",
        )
    return ledger


def validate_evidence_payload(
    value: Any,
    manifest: dict[str, Any],
    assets: dict[str, dict[str, Any]],
    manifest_identity: dict[str, Any],
    public_key_sha256: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    payload = exact_object(
        value,
        {"schema", "state", "candidate", "audit", "assets", "findings", "privacy", "ledger"},
        "independent-audit evidence payload",
    )
    require_literal(payload["schema"], EVIDENCE_SCHEMA, "independent-audit evidence schema")
    require_literal(payload["state"], "PASS", "independent-audit evidence state")
    candidate = validate_candidate(
        payload["candidate"], manifest, assets, manifest_identity, args
    )
    audit = validate_audit_identity(payload["audit"], args, public_key_sha256)
    validate_asset_records(payload["assets"], assets, args)
    validate_findings(payload["findings"], candidate)
    validate_privacy(payload["privacy"])
    validate_ledger_binding(payload["ledger"], args, audit)
    return payload


def parse_timestamp(value: Any, label: str) -> datetime:
    require_pattern(value, UTC_TIMESTAMP, label)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ContractError(f"{label} is not a valid UTC timestamp") from exc
    return parsed


def ledger_event_identity(
    payload: dict[str, Any], audit: dict[str, Any], args: argparse.Namespace
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate_identity = {
        "repository": args.repository,
        "tag": args.tag,
        "tag_object_sha": args.tag_object_sha,
        "commit": args.commit,
        "tree": args.tree,
    }
    audit_identity = {
        "auditor_repository": audit["auditor_repository"],
        "workflow_path": audit["workflow_path"],
        "workflow_sha": audit["workflow_sha"],
        "run_id": audit["run_id"],
        "run_attempt": audit["run_attempt"],
        "key_id": audit["key_id"],
    }
    del payload
    return candidate_identity, audit_identity


def validate_ledger_event(
    value: Any,
    event: str,
    sequence: int,
    expected_previous: str | None,
    evidence_digest: str,
    evidence_payload: dict[str, Any],
    args: argparse.Namespace,
) -> tuple[dict[str, Any], datetime]:
    payload = exact_object(
        value,
        {
            "schema",
            "event",
            "sequence",
            "created_at",
            "repository",
            "namespace",
            "candidate",
            "audit",
            "challenge_sha256",
            "previous_event_envelope_sha256",
            "evidence_envelope_sha256",
        },
        f"independent-audit ledger {event} payload",
    )
    require_literal(payload["schema"], LEDGER_EVENT_SCHEMA, "independent-audit ledger event schema")
    require_literal(payload["event"], event, "independent-audit ledger event")
    if payload["sequence"] != sequence:
        fail(f"independent-audit ledger {event} sequence differs")
    created_at = parse_timestamp(payload["created_at"], f"independent-audit ledger {event} time")
    ledger = evidence_payload["ledger"]
    audit = evidence_payload["audit"]
    candidate_identity, audit_identity = ledger_event_identity(payload, audit, args)
    if (
        payload["repository"] != ledger["repository"]
        or payload["namespace"] != ledger["namespace"]
        or payload["candidate"] != candidate_identity
        or payload["audit"] != audit_identity
        or payload["challenge_sha256"] != audit["challenge_sha256"]
        or payload["previous_event_envelope_sha256"] != expected_previous
    ):
        fail(f"independent-audit ledger {event} identity or chain differs")
    expected_evidence = evidence_digest if event == "result" else None
    if payload["evidence_envelope_sha256"] != expected_evidence:
        fail(f"independent-audit ledger {event} evidence digest differs")
    return payload, created_at


RemoteLoader = Callable[[str, str], tuple[str, str]]


def validate_ledger_proof(
    value: Any,
    evidence_envelope: dict[str, Any],
    evidence_payload: dict[str, Any],
    public_key: Path,
    key_id: str,
    args: argparse.Namespace,
    *,
    openssl: str = "openssl",
    remote_loader: RemoteLoader | None = None,
) -> dict[str, Any]:
    proof = exact_object(
        value,
        {"schema", "repository", "namespace", "ruleset_id", "ruleset_name", "refs"},
        "independent-audit ledger proof",
    )
    require_literal(proof["schema"], LEDGER_PROOF_SCHEMA, "independent-audit ledger proof schema")
    ledger = evidence_payload["ledger"]
    for key in ("repository", "namespace", "ruleset_id", "ruleset_name"):
        if proof[key] != ledger[key]:
            fail(f"independent-audit ledger proof differs at {key}")
    refs = exact_object(
        proof["refs"], {"reserved", "started", "result"}, "independent-audit ledger proof refs"
    )
    evidence_digest = sha256_bytes(canonical_bytes(evidence_envelope))
    previous_digest: str | None = None
    previous_time: datetime | None = None
    for sequence, event in enumerate(("reserved", "started", "result"), start=1):
        entry = exact_object(
            refs[event],
            {"ref", "tag_object_sha", "message_sha256", "envelope"},
            f"independent-audit ledger proof {event}",
        )
        require_literal(entry["ref"], ledger[f"{event}_ref"], f"independent-audit ledger {event} ref")
        require_pattern(entry["tag_object_sha"], HEX40, f"independent-audit ledger {event} tag object")
        require_pattern(entry["message_sha256"], HEX64, f"independent-audit ledger {event} message sha256")
        event_payload = verify_signed_envelope(
            entry["envelope"],
            public_key,
            key_id,
            expected_payload_schema=LEDGER_EVENT_SCHEMA,
            openssl=openssl,
        )
        _validated, created_at = validate_ledger_event(
            event_payload,
            event,
            sequence,
            previous_digest,
            evidence_digest,
            evidence_payload,
            args,
        )
        message = canonical_bytes(entry["envelope"])
        message_digest = sha256_bytes(message)
        if entry["message_sha256"] != message_digest:
            fail(f"independent-audit ledger {event} message digest differs")
        if previous_time is not None and created_at <= previous_time:
            fail("independent-audit ledger event timestamps are not strictly increasing")
        if remote_loader is not None:
            remote_sha, remote_message = remote_loader(ledger["repository"], entry["ref"])
            if remote_sha != entry["tag_object_sha"] or remote_message != message.decode("utf-8"):
                fail(f"remote independent-audit ledger {event} tag differs from proof")
        previous_digest = sha256_bytes(canonical_bytes(entry["envelope"]))
        previous_time = created_at
    return proof


def validate_args(args: argparse.Namespace) -> None:
    for field, label in (
        ("repository", "candidate repository"),
        ("tag", "candidate tag"),
        ("tag_object_sha", "candidate tag object sha"),
        ("commit", "candidate commit"),
        ("tree", "candidate tree"),
        ("public_key_sha256", "independent auditor public key sha256"),
        (
            "host_evaluator_public_key_sha256",
            "Host evaluator public key sha256",
        ),
        ("key_id", "independent auditor key id"),
        ("auditor_repository", "independent auditor repository"),
        ("auditor_workflow_name", "independent auditor workflow name"),
        ("auditor_workflow", "independent auditor workflow path"),
        ("auditor_ref", "independent auditor workflow ref"),
        ("auditor_workflow_sha", "independent auditor workflow sha"),
        ("challenge", "independent-audit challenge"),
        ("ledger_ruleset_name", "independent-audit ledger ruleset name"),
    ):
        required_text(getattr(args, field), label)
    args.auditor_run_id = positive_argument(
        args.auditor_run_id, "independent auditor run id"
    )
    args.auditor_run_attempt = positive_argument(
        args.auditor_run_attempt, "independent auditor run attempt"
    )
    args.ledger_ruleset_id = positive_argument(
        args.ledger_ruleset_id, "independent-audit ledger ruleset id"
    )
    require_pattern(args.repository, REPOSITORY, "candidate repository")
    require_literal(args.tag, TAG, "candidate tag")
    require_pattern(args.tag_object_sha, HEX40, "candidate tag object sha")
    require_pattern(args.commit, HEX40, "candidate commit")
    require_pattern(args.tree, HEX40, "candidate tree")
    require_pattern(args.public_key_sha256, HEX64, "independent auditor public key sha256")
    require_pattern(args.host_evaluator_public_key_sha256, HEX64, "Host evaluator public key sha256")
    if args.public_key_sha256 == args.host_evaluator_public_key_sha256:
        fail("independent auditor key must differ from the Host evaluator key")
    require_pattern(args.key_id, IDENTIFIER, "independent auditor key id")
    require_pattern(args.auditor_repository, REPOSITORY, "independent auditor repository")
    require_pattern(args.auditor_workflow, WORKFLOW_PATH, "independent auditor workflow path")
    require_pattern(args.auditor_ref, WORKFLOW_REF, "independent auditor workflow ref")
    require_pattern(args.auditor_workflow_sha, HEX40, "independent auditor workflow sha")
    if not isinstance(args.auditor_workflow_name, str) or not 3 <= len(args.auditor_workflow_name) <= 128:
        fail("independent auditor workflow name is invalid")
    challenge_sha256(args.challenge)
    require_pattern(args.ledger_ruleset_name, IDENTIFIER, "independent-audit ledger ruleset name")


def load_contract(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    evidence_path = require_present_file(args.evidence, "independent-audit evidence envelope")
    proof_path = require_present_file(args.proof, "independent-audit ledger proof")
    public_key = require_present_file(args.public_key, "independent auditor public key")
    asset_dir = require_asset_directory(args.asset_dir)
    validate_args(args)
    public_key_identity = regular_file_identity(
        public_key, "independent auditor public key", maximum=65_536
    )
    if public_key_identity["sha256"] != args.public_key_sha256:
        fail("independent auditor public key fingerprint differs")
    assets = asset_identities(asset_dir)
    manifest_path = asset_dir / "rc-release-manifest.json"
    manifest = load_canonical_json(
        manifest_path, "Round 9 publication manifest", maximum=4_194_304
    )
    manifest_identity = assets["rc-release-manifest.json"]
    validate_manifest(manifest, assets, args)
    evidence = load_canonical_json(
        evidence_path, "independent-audit evidence envelope", maximum=1_048_576
    )
    proof = load_canonical_json(
        proof_path, "independent-audit ledger proof", maximum=1_048_576
    )
    payload = verify_signed_envelope(
        evidence,
        public_key,
        args.key_id,
        expected_payload_schema=EVIDENCE_SCHEMA,
        openssl=args.openssl,
    )
    validate_evidence_payload(
        payload,
        manifest,
        assets,
        manifest_identity,
        public_key_identity["sha256"],
        args,
    )
    validate_ledger_proof(
        proof,
        evidence,
        payload,
        public_key,
        args.key_id,
        args,
        openssl=args.openssl,
    )
    return evidence, payload, proof


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        del req, fp, code, msg, headers, newurl
        return None


class GitHubClient:
    def __init__(self, token: str, api_url: str = "https://api.github.com"):
        if api_url != "https://api.github.com":
            fail("remote independent-audit verification requires https://api.github.com")
        self.api_url = api_url
        self.token = token
        self._opener = request.build_opener(_NoRedirect())

    def request(
        self, method: str, endpoint: str, *, allow_not_found: bool = False
    ) -> tuple[int, bytes]:
        operation = request.Request(
            self.api_url + "/" + endpoint.lstrip("/"),
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "cag-round9-independent-audit-contract/1",
            },
            method=method,
        )
        try:
            with self._opener.open(operation, timeout=60) as response:
                if 300 <= response.status < 400:
                    fail("GitHub API redirect was rejected")
                return response.status, response.read(4_194_305)
        except error.HTTPError as exc:
            try:
                raw = exc.read(1_048_577)
                status = exc.code
            finally:
                exc.close()
            if allow_not_found and status == 404:
                return 404, raw
            fail(f"GitHub API {method} {endpoint} failed with HTTP {status}")
        except (error.URLError, TimeoutError, OSError) as exc:
            raise ContractError("GitHub API request failed") from exc

    def json(self, endpoint: str) -> dict[str, Any]:
        status, raw = self.request("GET", endpoint)
        if status != 200 or len(raw) > 4_194_304:
            fail("GitHub API response is invalid")
        value = load_json_bytes(raw, "GitHub API response")
        if not isinstance(value, dict):
            fail("GitHub API response must be an object")
        return value

    def ref(
        self, repository: str, full_ref: str, *, absent_ok: bool = False
    ) -> dict[str, Any] | None:
        name = parse.quote(full_ref.removeprefix("refs/"), safe="/")
        status, raw = self.request(
            "GET", f"repos/{repository}/git/ref/{name}", allow_not_found=absent_ok
        )
        if status == 404 and absent_ok:
            return None
        value = load_json_bytes(raw, "Git reference")
        if not isinstance(value, dict):
            fail("Git reference response must be an object")
        return value


def remote_tag_message(
    client: GitHubClient,
    repository: str,
    full_ref: str,
    expected_commit: str,
) -> tuple[str, str]:
    ref = client.ref(repository, full_ref)
    if ref is None or ref.get("object", {}).get("type") != "tag":
        fail(f"remote independent-audit ledger reference is not an annotated tag: {full_ref}")
    tag_sha = require_pattern(
        ref["object"].get("sha"), HEX40, "remote independent-audit ledger tag object"
    )
    tag = client.json(f"repos/{repository}/git/tags/{tag_sha}")
    if tag.get("object", {}).get("type") != "commit" or tag["object"].get("sha") != expected_commit:
        fail("remote independent-audit ledger tag does not point to the exact candidate commit")
    message = tag.get("message")
    if not isinstance(message, str):
        fail("remote independent-audit ledger tag message is not text")
    value = load_json_bytes(message.encode("utf-8"), "remote independent-audit ledger tag message")
    if canonical_bytes(value).decode("utf-8") != message:
        fail("remote independent-audit ledger tag message is not canonical JSON")
    return tag_sha, message


def verify_ruleset(client: GitHubClient, args: argparse.Namespace) -> None:
    ruleset = client.json(f"repos/{args.repository}/rulesets/{args.ledger_ruleset_id}")
    if (
        ruleset.get("id") != args.ledger_ruleset_id
        or ruleset.get("name") != args.ledger_ruleset_name
        or ruleset.get("target") != "tag"
        or ruleset.get("enforcement") != "active"
        or ruleset.get("bypass_actors") != []
    ):
        fail("independent-audit ledger ruleset identity/enforcement differs")
    conditions = ruleset.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    includes = ref_name.get("include") if isinstance(ref_name, dict) else None
    excludes = ref_name.get("exclude") if isinstance(ref_name, dict) else None
    if not isinstance(includes, list) or not any(
        item
        in {
            "~ALL",
            "refs/tags/round9-independent-audit-ledger/**",
            "refs/tags/round9-independent-audit-ledger/**/*",
        }
        for item in includes
    ):
        fail("independent-audit ledger ruleset does not cover the protected namespace")
    if excludes != []:
        fail("independent-audit ledger ruleset must not exclude protected references")
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or not all(
        isinstance(item, dict)
        and isinstance(item.get("type"), str)
        and bool(item["type"])
        for item in rules
    ):
        fail("independent-audit ledger ruleset contains malformed rule entries")
    types = {item["type"] for item in rules}
    if not {"deletion", "update"}.issubset(types):
        fail("independent-audit ledger ruleset does not prohibit deletion and update")


def verify_remote(
    args: argparse.Namespace,
    evidence: dict[str, Any],
    payload: dict[str, Any],
    proof: dict[str, Any],
) -> None:
    token = os.environ.get("GH_TOKEN", "")
    if not token or "\n" in token or "\r" in token:
        fail("GH_TOKEN is required for remote independent-audit verification")
    client = GitHubClient(token)
    main = client.ref(args.repository, "refs/heads/main")
    if main is None or main.get("object", {}).get("type") != "commit" or main.get("object", {}).get("sha") != args.commit:
        fail("remote main does not equal the independent-audited candidate commit")
    tag_ref = client.ref(args.repository, f"refs/tags/{args.tag}")
    if (
        tag_ref is None
        or tag_ref.get("object", {}).get("type") != "tag"
        or tag_ref.get("object", {}).get("sha") != args.tag_object_sha
    ):
        fail("remote independent-audited candidate tag differs")
    tag = client.json(f"repos/{args.repository}/git/tags/{args.tag_object_sha}")
    if tag.get("object", {}).get("type") != "commit" or tag.get("object", {}).get("sha") != args.commit:
        fail("remote independent-audited candidate tag object differs")
    commit = client.json(f"repos/{args.repository}/git/commits/{args.commit}")
    if commit.get("tree", {}).get("sha") != args.tree:
        fail("remote independent-audited candidate tree differs")
    audit_run = client.json(
        f"repos/{args.auditor_repository}/actions/runs/{args.auditor_run_id}"
    )
    if not (
        audit_run.get("id") == args.auditor_run_id
        and audit_run.get("run_attempt") == args.auditor_run_attempt
        and audit_run.get("name") == args.auditor_workflow_name
        and audit_run.get("path") == args.auditor_workflow
        and audit_run.get("head_sha") == args.auditor_workflow_sha
        and audit_run.get("event") == "workflow_dispatch"
        and audit_run.get("status") == "completed"
        and audit_run.get("conclusion") == "success"
        and audit_run.get("repository", {}).get("full_name") == args.auditor_repository
    ):
        fail("remote independent-audit workflow run identity differs")
    artifact = client.json(
        f"repos/{args.auditor_repository}/actions/artifacts/{args.audit_artifact_id}"
    )
    if not (
        artifact.get("id") == args.audit_artifact_id
        and artifact.get("name") == args.audit_artifact_name
        and artifact.get("digest") == args.audit_artifact_digest
        and artifact.get("expired") is False
        and artifact.get("workflow_run", {}).get("id") == args.auditor_run_id
    ):
        fail("remote independent-audit artifact identity differs")
    verify_ruleset(client, args)
    if client.ref(
        args.repository,
        ledger_ref(payload["ledger"]["namespace"], "aborted"),
        absent_ok=True,
    ) is not None:
        fail("remote independent-audit ledger contains an aborted event")

    def loader(repository: str, full_ref: str) -> tuple[str, str]:
        return remote_tag_message(client, repository, full_ref, args.commit)

    public_key = Path(args.public_key)
    validate_ledger_proof(
        proof,
        evidence,
        payload,
        public_key,
        args.key_id,
        args,
        openssl=args.openssl,
        remote_loader=loader,
    )


def add_common(command: argparse.ArgumentParser) -> None:
    command.add_argument("--evidence", required=True)
    command.add_argument("--proof", required=True)
    command.add_argument("--asset-dir", required=True)
    command.add_argument("--public-key", required=True)
    command.add_argument("--public-key-sha256", required=True)
    command.add_argument("--host-evaluator-public-key-sha256", required=True)
    command.add_argument("--key-id", required=True)
    command.add_argument("--repository", required=True)
    command.add_argument("--tag", required=True)
    command.add_argument("--tag-object-sha", required=True)
    command.add_argument("--commit", required=True)
    command.add_argument("--tree", required=True)
    command.add_argument("--challenge", required=True)
    command.add_argument("--auditor-repository", required=True)
    command.add_argument("--auditor-workflow-name", required=True)
    command.add_argument("--auditor-workflow", required=True)
    command.add_argument("--auditor-ref", required=True)
    command.add_argument("--auditor-workflow-sha", required=True)
    command.add_argument("--auditor-run-id", required=True)
    command.add_argument("--auditor-run-attempt", required=True)
    command.add_argument("--ledger-ruleset-id", required=True)
    command.add_argument("--ledger-ruleset-name", required=True)
    command.add_argument("--openssl", default="openssl")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    add_common(validate)
    remote = commands.add_parser("verify-remote")
    add_common(remote)
    remote.add_argument("--audit-artifact-id", required=True)
    remote.add_argument("--audit-artifact-name", required=True)
    remote.add_argument("--audit-artifact-digest", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        evidence, payload, proof = load_contract(args)
        if args.command == "verify-remote":
            args.audit_artifact_id = positive_argument(
                args.audit_artifact_id, "independent-audit artifact id"
            )
            required_text(args.audit_artifact_name, "independent-audit artifact name")
            required_text(args.audit_artifact_digest, "independent-audit artifact digest")
            if not 3 <= len(args.audit_artifact_name) <= 128:
                fail("independent-audit artifact name is invalid")
            require_pattern(
                args.audit_artifact_digest,
                SHA256_DIGEST,
                "independent-audit artifact digest",
            )
            verify_remote(args, evidence, payload, proof)
    except EvidenceNotProvided as exc:
        print(f"round9-independent-audit: NOT_PROVIDED: {exc}", file=sys.stderr)
        return 3
    except ContractError as exc:
        print(f"round9-independent-audit: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "round9-independent-audit: PASS "
        f"evidence_sha256={sha256_bytes(canonical_bytes(evidence))} "
        f"ledger_proof_sha256={sha256_bytes(canonical_bytes(proof))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
