#!/usr/bin/env python3
"""Validate the signed external Round 9 evaluation and protected Git ledger."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any
from urllib import error, parse, request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools" / "round9-eval"))

from round9_eval_core import (  # noqa: E402
    EVALUATION_SCHEMA,
    ContractError,
    HEX40,
    HEX64,
    IDENTIFIER,
    REPOSITORY,
    SHA256_DIGEST,
    canonical_bytes,
    exact_int,
    ledger_ref,
    load_canonical_json,
    load_json_bytes,
    require_pattern,
    sha256_bytes,
    sha256_file,
    validate_candidate,
    validate_counted_mock,
    validate_development_evidence,
    validate_evaluation_payload,
    validate_ledger_proof,
    validate_runtime_checks,
    verify_signed_envelope,
)


TAG = "v0.16-rc.4"
RELEASE_WORKFLOW = ".github/workflows/round9-release-rc.yml"
PHASE1_WORKFLOW_NAME = "Round 9 RC release v0.16-rc.4 - Linux counted-Mock admission"
HOST_WORKFLOW = ".github/workflows/round9-host-validation.yml"
HOST_WORKFLOW_NAME = "Round 9 protected CPA Host validation"


def fail(message: str) -> None:
    raise ContractError(message)


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        del req, fp, code, msg, headers, newurl
        return None


class GitHubClient:
    def __init__(self, token: str, api_url: str = "https://api.github.com"):
        if api_url != "https://api.github.com":
            fail("remote verification requires https://api.github.com")
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
                "User-Agent": "cag-round9-external-evaluation-contract/1",
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

    def ref(self, repository: str, full_ref: str, *, absent_ok: bool = False) -> dict[str, Any] | None:
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


def expected_candidate(args: argparse.Namespace) -> dict[str, Any]:
    return validate_candidate(
        {
            "tag": args.tag,
            "tag_object_sha": args.tag_object_sha,
            "source_version": "0.16",
            "commit": args.commit,
            "tree": args.tree,
            "so_sha256": args.so_sha256,
            "cpa_version": "v7.2.103",
            "cpa_commit": "cade44b9cdee6b9328ea2648fd119129fdf11e2d",
            "classifier_policy_version": args.classifier_policy_version,
            "classifier_policy_sha256": args.classifier_policy_sha256,
            "ruleset_version": args.ruleset_version,
            "ruleset_sha256": args.ruleset_sha256,
            "ruleset_manifest_sha256": args.ruleset_manifest_sha256,
            "build_metadata_sha256": args.build_metadata_sha256,
            "release_manifest_sha256": args.release_manifest_sha256,
            "phase1_run_id": args.phase1_run_id,
            "phase1_run_attempt": args.phase1_run_attempt,
            "phase1_artifact_id": args.phase1_artifact_id,
            "phase1_artifact_digest": args.phase1_artifact_digest,
        }
    )


def load_contract(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    for path, label in (
        (args.envelope, "external evaluation envelope"),
        (args.proof, "external ledger proof"),
        (args.development_evidence, "Round 9 development evidence"),
    ):
        load_canonical_json(path, label, maximum=1_048_576)
    if sha256_file(args.public_key) != args.public_key_sha256:
        fail("external evaluator public key fingerprint differs")
    envelope = load_canonical_json(args.envelope, "external evaluation envelope")
    proof = load_canonical_json(args.proof, "external ledger proof")
    development_evidence = load_canonical_json(
        args.development_evidence,
        "Round 9 development evidence",
        maximum=1_048_576,
    )
    payload = verify_signed_envelope(
        envelope,
        args.public_key,
        args.key_id,
        expected_payload_schema=EVALUATION_SCHEMA,
        openssl=args.openssl,
    )
    candidate = expected_candidate(args)
    validate_development_evidence(development_evidence, expected_candidate=candidate)
    validate_evaluation_payload(payload, expected_candidate=candidate, challenge=args.challenge)
    if payload["development_evidence"] != development_evidence:
        fail("signed external evaluation development evidence differs")
    validate_runtime_checks(payload["metrics"]["runtime_checks"])
    validate_counted_mock(payload["counted_mock"], payload["metrics"], payload["execution"])
    if payload["evaluator"]["version"] != args.evaluator_version:
        fail("external evaluator version differs")
    if payload["evaluator"]["sha256"] != args.evaluator_sha256:
        fail("external evaluator SHA-256 differs")
    if payload["evaluator"]["core_sha256"] != args.core_sha256:
        fail("external evaluator core SHA-256 differs")
    if payload["evaluator"]["broker_sha256"] != args.broker_sha256:
        fail("external evaluation broker SHA-256 differs")
    execution = payload["execution"]
    expected_execution = {
        "workflow_run_id": args.host_run_id,
        "workflow_run_attempt": args.host_run_attempt,
        "cpa_image_id": args.cpa_image_id,
        "counted_mock_image_id": args.counted_mock_image_id,
        "model": args.model,
        "scan_limit_bytes": 16_384,
        "sandbox_adapter_sha256": args.sandbox_adapter_sha256,
        "sandbox_adapter_config_sha256": args.sandbox_adapter_config_sha256,
        "docker_sandbox_sha256": args.docker_sandbox_sha256,
    }
    for key, expected in expected_execution.items():
        if execution.get(key) != expected:
            fail(f"external execution identity differs at {key}")
    if payload["ledger"]["repository"] != args.repository:
        fail("external ledger repository differs")
    return envelope, payload, proof


def remote_tag_message(
    client: GitHubClient,
    repository: str,
    full_ref: str,
    expected_commit: str,
) -> tuple[str, str]:
    ref = client.ref(repository, full_ref)
    if ref is None or ref.get("object", {}).get("type") != "tag":
        fail(f"remote ledger reference is not an annotated tag: {full_ref}")
    tag_sha = require_pattern(ref["object"].get("sha"), HEX40, "remote ledger tag object")
    tag = client.json(f"repos/{repository}/git/tags/{tag_sha}")
    if tag.get("object", {}).get("type") != "commit" or tag["object"].get("sha") != expected_commit:
        fail("remote ledger tag does not point to the exact candidate commit")
    message = tag.get("message")
    if not isinstance(message, str):
        fail("remote ledger tag message is not text")
    value = load_json_bytes(message.encode("utf-8"), "remote ledger tag message")
    if canonical_bytes(value).decode("utf-8") != message:
        fail("remote ledger tag message is not canonical JSON")
    return tag_sha, message


def verify_ruleset(client: GitHubClient, args: argparse.Namespace) -> None:
    ruleset = client.json(f"repos/{args.repository}/rulesets/{args.ruleset_id}")
    if (
        ruleset.get("id") != args.ruleset_id
        or ruleset.get("name") != args.ruleset_name
        or ruleset.get("target") != "tag"
        or ruleset.get("enforcement") != "active"
        or ruleset.get("bypass_actors") != []
    ):
        fail("protected ledger ruleset identity/enforcement differs")
    conditions = ruleset.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    includes = ref_name.get("include") if isinstance(ref_name, dict) else None
    excludes = ref_name.get("exclude") if isinstance(ref_name, dict) else None
    if not isinstance(includes, list) or not any(
        item in {"~ALL", "refs/tags/round9-eval-ledger/**", "refs/tags/round9-eval-ledger/**/*"}
        for item in includes
    ):
        fail("protected ledger ruleset does not cover the Round 9 namespace")
    if excludes != []:
        fail("protected ledger ruleset must not exclude protected ledger references")
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or not all(
        isinstance(item, dict)
        and isinstance(item.get("type"), str)
        and bool(item["type"])
        for item in rules
    ):
        fail("protected ledger ruleset contains malformed rule entries")
    types = {item["type"] for item in rules}
    if not {"deletion", "update"}.issubset(types):
        fail("protected ledger ruleset does not prohibit deletion and update")


def verify_remote(
    args: argparse.Namespace,
    envelope: dict[str, Any],
    payload: dict[str, Any],
    proof: dict[str, Any],
) -> None:
    token = os.environ.get("GH_TOKEN", "")
    if not token or "\n" in token or "\r" in token:
        fail("GH_TOKEN is required for remote ledger verification")
    client = GitHubClient(token)
    main = client.ref(args.repository, "refs/heads/main")
    if main is None or main.get("object", {}).get("sha") != args.commit:
        fail("remote main does not equal the candidate commit")
    tag_ref = client.ref(args.repository, f"refs/tags/{args.tag}")
    if tag_ref is None or tag_ref.get("object", {}).get("type") != "tag" or tag_ref["object"].get("sha") != args.tag_object_sha:
        fail("remote candidate tag reference differs")
    tag = client.json(f"repos/{args.repository}/git/tags/{args.tag_object_sha}")
    if tag.get("object", {}).get("type") != "commit" or tag["object"].get("sha") != args.commit:
        fail("remote candidate tag object differs")
    commit = client.json(f"repos/{args.repository}/git/commits/{args.commit}")
    if commit.get("tree", {}).get("sha") != args.tree:
        fail("remote candidate tree differs")
    phase1 = client.json(f"repos/{args.repository}/actions/runs/{args.phase1_run_id}")
    if not (
        phase1.get("id") == args.phase1_run_id
        and phase1.get("run_attempt") == args.phase1_run_attempt
        and phase1.get("name") == PHASE1_WORKFLOW_NAME
        and phase1.get("path") == RELEASE_WORKFLOW
        and phase1.get("head_sha") == args.commit
        and phase1.get("status") == "completed"
        and phase1.get("conclusion") == "success"
    ):
        fail("remote Phase 1 workflow run differs")
    artifact = client.json(
        f"repos/{args.repository}/actions/artifacts/{args.phase1_artifact_id}"
    )
    if not (
        artifact.get("id") == args.phase1_artifact_id
        and artifact.get("digest") == args.phase1_artifact_digest
        and artifact.get("expired") is False
        and artifact.get("workflow_run", {}).get("id") == args.phase1_run_id
    ):
        fail("remote Phase 1 artifact differs")
    host = client.json(f"repos/{args.repository}/actions/runs/{args.host_run_id}")
    if not (
        host.get("id") == args.host_run_id
        and host.get("run_attempt") == args.host_run_attempt
        and host.get("name") == HOST_WORKFLOW_NAME
        and host.get("path") == HOST_WORKFLOW
        and host.get("head_sha") == args.commit
        and host.get("event") == "workflow_dispatch"
        and host.get("status") == "completed"
        and host.get("conclusion") == "success"
    ):
        fail("remote external Host workflow run differs")
    verify_ruleset(client, args)
    if client.ref(
        args.repository,
        ledger_ref(payload["ledger"]["namespace"], "aborted"),
        absent_ok=True,
    ) is not None:
        fail("remote ledger contains an aborted event")

    def loader(repository: str, full_ref: str) -> tuple[str, str]:
        return remote_tag_message(client, repository, full_ref, args.commit)

    validate_ledger_proof(
        proof,
        envelope,
        payload,
        args.public_key,
        args.key_id,
        remote_loader=loader,
    )


def add_common(command: argparse.ArgumentParser) -> None:
    command.add_argument("--envelope", required=True, type=Path)
    command.add_argument("--proof", required=True, type=Path)
    command.add_argument("--development-evidence", required=True, type=Path)
    command.add_argument("--public-key", required=True, type=Path)
    command.add_argument("--public-key-sha256", required=True)
    command.add_argument("--key-id", required=True)
    command.add_argument("--evaluator-version", required=True)
    command.add_argument("--evaluator-sha256", required=True)
    command.add_argument("--core-sha256", required=True)
    command.add_argument("--broker-sha256", required=True)
    command.add_argument("--sandbox-adapter-sha256", required=True)
    command.add_argument("--sandbox-adapter-config-sha256", required=True)
    command.add_argument("--docker-sandbox-sha256", required=True)
    command.add_argument("--cpa-image-id", required=True)
    command.add_argument("--counted-mock-image-id", required=True)
    command.add_argument("--model", required=True)
    command.add_argument("--repository", required=True)
    command.add_argument("--tag", required=True)
    command.add_argument("--tag-object-sha", required=True)
    command.add_argument("--commit", required=True)
    command.add_argument("--tree", required=True)
    command.add_argument("--so-sha256", required=True)
    command.add_argument("--classifier-policy-version", required=True)
    command.add_argument("--classifier-policy-sha256", required=True)
    command.add_argument("--ruleset-version", required=True)
    command.add_argument("--ruleset-sha256", required=True)
    command.add_argument("--ruleset-manifest-sha256", required=True)
    command.add_argument("--build-metadata-sha256", required=True)
    command.add_argument("--release-manifest-sha256", required=True)
    command.add_argument("--phase1-run-id", required=True, type=int)
    command.add_argument("--phase1-run-attempt", required=True, type=int)
    command.add_argument("--phase1-artifact-id", required=True, type=int)
    command.add_argument("--phase1-artifact-digest", required=True)
    command.add_argument("--host-run-id", required=True, type=int)
    command.add_argument("--host-run-attempt", required=True, type=int)
    command.add_argument("--challenge", required=True)
    command.add_argument("--openssl", default="openssl")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    offline = commands.add_parser("validate")
    add_common(offline)
    remote = commands.add_parser("verify-remote")
    add_common(remote)
    remote.add_argument("--ruleset-id", required=True, type=int)
    remote.add_argument("--ruleset-name", required=True)
    return result


def validate_args(args: argparse.Namespace) -> None:
    require_pattern(args.public_key_sha256, HEX64, "public key SHA-256")
    require_pattern(args.key_id, IDENTIFIER, "evaluator key id")
    require_pattern(args.evaluator_version, IDENTIFIER, "evaluator version")
    require_pattern(args.evaluator_sha256, HEX64, "evaluator SHA-256")
    for name in (
        "core_sha256",
        "broker_sha256",
        "sandbox_adapter_sha256",
        "sandbox_adapter_config_sha256",
        "docker_sandbox_sha256",
    ):
        require_pattern(getattr(args, name), HEX64, name.replace("_", " "))
    for name in ("cpa_image_id", "counted_mock_image_id"):
        require_pattern(getattr(args, name), SHA256_DIGEST, name.replace("_", " "))
    if (
        not isinstance(args.model, str)
        or any(
            marker in args.model.casefold()
            for marker in ("round9", "eval", "mock", "corpus", "holdout", "test")
        )
    ):
        fail("external evaluation model must be an ordinary identity")
    require_pattern(args.repository, REPOSITORY, "repository")
    if args.tag != TAG:
        fail(f"candidate tag must be {TAG}")
    require_pattern(args.tag_object_sha, HEX40, "candidate tag object")
    require_pattern(args.commit, HEX40, "candidate commit")
    require_pattern(args.tree, HEX40, "candidate tree")
    require_pattern(args.so_sha256, HEX64, "candidate SO SHA-256")
    require_pattern(args.classifier_policy_version, IDENTIFIER, "classifier policy version")
    require_pattern(args.classifier_policy_sha256, HEX64, "classifier policy SHA-256")
    if args.ruleset_version != "1.0.10":
        fail("candidate ruleset version must be 1.0.10")
    for name in (
        "ruleset_sha256",
        "ruleset_manifest_sha256",
        "build_metadata_sha256",
        "release_manifest_sha256",
    ):
        require_pattern(getattr(args, name), HEX64, name.replace("_", " "))
    require_pattern(args.phase1_artifact_digest, SHA256_DIGEST, "Phase 1 artifact digest")
    require_pattern(args.challenge, HEX64, "workflow challenge")
    for name in (
        "phase1_run_id",
        "phase1_run_attempt",
        "phase1_artifact_id",
        "host_run_id",
        "host_run_attempt",
    ):
        exact_int(getattr(args, name), name, minimum=1)
    if args.command == "verify-remote":
        exact_int(args.ruleset_id, "ruleset id", minimum=1)
        require_pattern(args.ruleset_name, IDENTIFIER, "ruleset name")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        validate_args(args)
        envelope, payload, proof = load_contract(args)
        validate_ledger_proof(
            proof,
            envelope,
            payload,
            args.public_key,
            args.key_id,
        )
        if args.command == "verify-remote":
            verify_remote(args, envelope, payload, proof)
    except (ContractError, OSError, ValueError) as exc:
        print(f"Round 9 external evaluation contract: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "Round 9 external evaluation contract: PASS "
        f"mode={args.command} envelope_sha256={sha256_bytes(canonical_bytes(envelope))} "
        f"proof_sha256={sha256_bytes(canonical_bytes(proof))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
