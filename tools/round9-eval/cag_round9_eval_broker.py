#!/usr/bin/env python3
"""Root-owned Round 9 independent-evaluation broker.

The GitHub job supplies immutable identity values only. Executable paths,
credentials, corpus hashes, signing keys, sandbox identity and the one-shot
ledger ruleset are all read from a fixed root-owned configuration file.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any
from urllib import error, parse, request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import round9_eval_core as core_module  # noqa: E402

from round9_eval_core import (  # noqa: E402
    EVALUATION_SCHEMA,
    EVALUATOR_AGGREGATE_SCHEMA,
    FIXED_NETWORK_BINDING,
    FIXED_PHASE_PROTOCOL,
    LEDGER_EVENT_SCHEMA,
    LEDGER_PROOF_SCHEMA,
    ContractError,
    HEX40,
    HEX64,
    IDENTIFIER,
    REPOSITORY,
    SHA256_DIGEST,
    atomic_write,
    canonical_bytes,
    challenge_sha256,
    derive_counted_mock,
    exact_bool,
    exact_int,
    exact_object,
    ledger_namespace,
    ledger_ref,
    load_canonical_json,
    load_json,
    load_json_bytes,
    load_public_counted_mock_corpus,
    merge_public_counted_mock,
    require_literal,
    require_pattern,
    require_root_owned_regular,
    sha256_bytes,
    sha256_file,
    signed_envelope,
    validate_candidate,
    validate_counted_mock,
    validate_corpus,
    validate_development_evidence,
    validate_decision_audit,
    validate_evaluation_payload,
    validate_evaluator,
    validate_execution,
    validate_ledger_proof,
    validate_ledger_event_payload,
    validate_metrics,
    validate_privacy,
    validate_public_counted_mock,
    validate_public_counted_mock_transport,
    validate_runtime_checks,
    verify_signed_envelope,
)


CONFIG_PATH = Path("/etc/cag-round9-eval-broker/config.json")
CONFIG_SCHEMA = "round9-eval-broker-config/v1"
ADAPTER_CONFIG_SCHEMA = "round9-cpa-sandbox-adapter-config/v1"
TAG = "v0.16-rc.3"
RELEASE_WORKFLOW = ".github/workflows/round9-release-rc.yml"
HOST_WORKFLOW = ".github/workflows/round9-host-validation.yml"
HOST_WORKFLOW_NAME = "Round 9 protected CPA Host validation"
PHASE1_WORKFLOW_NAME = "Round 9 RC release v0.16-rc.3 - Linux counted-Mock admission"
SO_NAME = "cyber-abuse-guard-v0.16-rc.3.so"
ARTIFACT_NAMES = {
    "build-metadata.json",
    "checksums.txt",
    SO_NAME,
    f"{SO_NAME}.sha256",
    "cyber-abuse-guard_0.16-rc.3_linux_amd64.zip",
    "cyber-abuse-guard-v0.16-rc.3-audit-bundle.zip",
    "cyber-abuse-guard-v0.16-rc.3-source.tar.gz",
    "cyber-abuse-guard-v0.16-rc.3-source.tar.gz.sha256",
    "rc-release-evidence.md",
    "rc-release-evidence.md.sha256",
    "rc-release-manifest.json",
    "rc-release-manifest.json.sha256",
    "rc-release-test-summary.txt",
    "rc-release-test-summary.txt.sha256",
    "ruleset-manifest.json",
    "ruleset.sha256",
    "sbom.cdx.json",
}
CORPUS_ARCHIVE_NAMES = {
    "bundle-manifest.signed.json",
    "benign-manifest.json",
    "benign-cases.jsonl",
    "malicious-manifest.json",
    "malicious-cases.jsonl",
}
RULESET_PATHS = {
    "rules/contexts.yaml",
    "rules/credentials.yaml",
    "rules/disruption.yaml",
    "rules/evasion.yaml",
    "rules/exfiltration.yaml",
    "rules/exploitation.yaml",
    "rules/malware.yaml",
    "rules/manifest.yaml",
    "rules/phishing.yaml",
    "rules/ransomware.yaml",
    "rules/semantics.yaml",
}
CANDIDATE_IDENTITY_INPUT_KEYS = (
    "so_sha256",
    "classifier_policy_version",
    "classifier_policy_sha256",
    "ruleset_version",
    "ruleset_sha256",
    "ruleset_manifest_sha256",
    "build_metadata_sha256",
    "release_manifest_sha256",
)


class _NoRedirect(request.HTTPRedirectHandler):
    """Treat every redirect as a response so credentials never follow it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        del req, fp, code, msg, headers, newurl
        return None


def _no_redirect_opener(*, use_environment_proxy: bool) -> request.OpenerDirector:
    handlers: list[Any] = [_NoRedirect()]
    if not use_environment_proxy:
        handlers.insert(0, request.ProxyHandler({}))
    return request.build_opener(*handlers)


def minimal_subprocess_env(*, home: str = "/root", github_token: str | None = None) -> dict[str, str]:
    """Return the complete environment allowed to reach a broker child process."""

    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": home,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
    }
    if github_token is not None:
        environment["GH_TOKEN"] = github_token
    return environment


def fail(message: str) -> None:
    raise ContractError(message)


def apply_candidate_identity_input(args: argparse.Namespace) -> dict[str, Any]:
    raw = getattr(args, "candidate_identity", None)
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > 4096:
        fail("candidate identity input is missing or exceeds the reviewed bound")
    value = exact_object(
        load_json_bytes(raw.encode("utf-8"), "candidate identity input"),
        set(CANDIDATE_IDENTITY_INPUT_KEYS),
        "candidate identity input",
    )
    if canonical_bytes(value).decode("utf-8").removesuffix("\n") != raw:
        fail("candidate identity input must be canonical inline JSON")
    for key in CANDIDATE_IDENTITY_INPUT_KEYS:
        setattr(args, key, value[key])
    return value


def read_secret(path: Path, label: str, *, maximum: int = 65_536) -> str:
    require_root_owned_regular(path, label, mode_mask=0o077)
    raw = path.read_bytes()
    if not raw or len(raw) > maximum or b"\0" in raw:
        fail(f"{label} is empty or exceeds the reviewed bound")
    text = raw.decode("utf-8").strip()
    if not text or "\n" in text or "\r" in text:
        fail(f"{label} must be one line")
    return text


def require_root_directory(path: Path, label: str) -> Path:
    info = path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_uid != 0 or info.st_mode & 0o077:
        fail(f"{label} must be a root-owned 0700-style directory")
    return path.resolve()


def require_fixed_executable(path: Path, digest: str, label: str) -> Path:
    require_root_owned_regular(path, label, mode_mask=0o022)
    if not os.access(path, os.X_OK):
        fail(f"{label} is not executable")
    if sha256_file(path) != require_pattern(digest, HEX64, f"{label} sha256"):
        fail(f"{label} differs from the root-pinned SHA-256")
    return path.resolve()


def require_fixed_file(path: Path, digest: str, label: str) -> Path:
    require_root_owned_regular(path, label, mode_mask=0o022)
    if sha256_file(path) != require_pattern(digest, HEX64, f"{label} sha256"):
        fail(f"{label} differs from the root-pinned SHA-256")
    return path.resolve()


def canonical_ed25519_public_spki(
    key_path: Path, *, private_key: bool, openssl: str
) -> bytes:
    """Return the OpenSSL-canonical DER SPKI for one Ed25519 key."""

    command = [openssl, "pkey"]
    if not private_key:
        command.append("-pubin")
    command.extend(["-in", str(key_path), "-pubout", "-outform", "DER"])
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=minimal_subprocess_env(),
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        fail("OpenSSL failed to canonicalize an evaluation signing key")
    der = completed.stdout
    # RFC 8410 Ed25519 SubjectPublicKeyInfo: SEQUENCE(AlgorithmIdentifier
    # id-Ed25519, BIT STRING containing the 32-byte public key).
    if len(der) != 44 or not der.startswith(bytes.fromhex("302a300506032b6570032100")):
        fail("evaluation signing key is not canonical Ed25519 SPKI")
    return der


def validate_signing_key_material(
    evaluator_private_key: Path,
    evaluator_public_key: Path,
    author_public_key: Path,
    *,
    openssl: str,
) -> None:
    evaluator_from_private = canonical_ed25519_public_spki(
        evaluator_private_key, private_key=True, openssl=openssl
    )
    evaluator_public = canonical_ed25519_public_spki(
        evaluator_public_key, private_key=False, openssl=openssl
    )
    if evaluator_from_private != evaluator_public:
        fail("evaluator private/public signing keys do not match")
    author_public = canonical_ed25519_public_spki(
        author_public_key, private_key=False, openssl=openssl
    )
    if sha256_bytes(author_public) == sha256_bytes(evaluator_public):
        fail("corpus author and evaluator signing key material must be distinct")


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    require_root_owned_regular(path, "broker configuration", mode_mask=0o077)
    config = exact_object(
        load_json(path, "broker configuration", maximum=262_144),
        {
            "schema",
            "repository",
            "github",
            "paths",
            "identities",
            "signing",
            "corpus",
            "sandbox",
        },
        "broker configuration",
    )
    require_literal(config["schema"], CONFIG_SCHEMA, "broker configuration schema")
    require_pattern(config["repository"], REPOSITORY, "broker repository")
    github = exact_object(
        config["github"],
        {"api_url", "token_file", "ledger_ruleset_id", "ledger_ruleset_name"},
        "broker GitHub configuration",
    )
    if github["api_url"] != "https://api.github.com":
        fail("broker GitHub API URL must remain https://api.github.com")
    exact_int(github["ledger_ruleset_id"], "ledger ruleset id", minimum=1)
    require_pattern(github["ledger_ruleset_name"], IDENTIFIER, "ledger ruleset name")

    paths = exact_object(
        config["paths"],
        {
            "work_root",
            "state_root",
            "allowed_output_root",
            "broker",
            "core",
            "evaluator",
            "docker_sandbox",
            "sandbox_adapter",
            "sandbox_adapter_config",
            "age",
            "openssl",
            "gh",
        },
        "broker paths",
    )
    identities = exact_object(
        config["identities"],
        {
            "evaluator_version",
            "broker_sha256",
            "core_sha256",
            "evaluator_sha256",
            "docker_sandbox_sha256",
            "sandbox_adapter_sha256",
            "sandbox_adapter_config_sha256",
            "evaluator_key_id",
            "author_key_id",
        },
        "broker identities",
    )
    for key in ("evaluator_version", "evaluator_key_id", "author_key_id"):
        require_pattern(identities[key], IDENTIFIER, f"broker {key}")
    for key in (
        "broker_sha256",
        "core_sha256",
        "evaluator_sha256",
        "docker_sandbox_sha256",
        "sandbox_adapter_sha256",
        "sandbox_adapter_config_sha256",
    ):
        require_pattern(identities[key], HEX64, f"broker {key}")

    signing = exact_object(
        config["signing"], {"private_key", "public_key"}, "broker signing configuration"
    )
    corpus = exact_object(
        config["corpus"],
        {
            "encrypted_bundle",
            "encrypted_bundle_sha256",
            "age_identity",
            "author_public_key",
            "evaluation_id",
            "bundle_manifest_sha256",
            "benign_manifest_sha256",
            "benign_cases_sha256",
            "malicious_manifest_sha256",
            "malicious_cases_sha256",
        },
        "broker corpus configuration",
    )
    require_pattern(corpus["evaluation_id"], IDENTIFIER, "corpus evaluation id")
    for key in (
        "encrypted_bundle_sha256",
        "bundle_manifest_sha256",
        "benign_manifest_sha256",
        "benign_cases_sha256",
        "malicious_manifest_sha256",
        "malicious_cases_sha256",
    ):
        require_pattern(corpus[key], HEX64, f"corpus {key}")
    sandbox = exact_object(
        config["sandbox"],
        {
            "sandbox_id",
            "daemon_id",
            "probe_image_id",
            "cpa_image_id",
            "counted_mock_image_id",
            "model",
            "scan_limit_bytes",
        },
        "broker sandbox",
    )
    require_pattern(sandbox["sandbox_id"], IDENTIFIER, "sandbox id")
    require_pattern(sandbox["daemon_id"], IDENTIFIER, "sandbox daemon id")
    for key in ("probe_image_id", "cpa_image_id", "counted_mock_image_id"):
        if not isinstance(sandbox[key], str) or not sandbox[key].startswith("sha256:"):
            fail(f"sandbox {key} is invalid")
        require_pattern(sandbox[key][7:], HEX64, f"sandbox {key}")
    model = sandbox["model"]
    if (
        not isinstance(model, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", model) is None
        or any(
            marker in model.casefold()
            for marker in ("round9", "eval", "mock", "corpus", "holdout", "test")
        )
    ):
        fail("broker sandbox model is not an ordinary model identity")
    if exact_int(sandbox["scan_limit_bytes"], "broker sandbox scan limit") != 16_384:
        fail("broker sandbox scan limit must remain exactly 16 KiB")

    # Resolve and validate every authority-bearing path before accepting data
    # supplied by a workflow dispatch.
    config["_config_path"] = path.resolve()
    config["_work_root"] = require_root_directory(Path(paths["work_root"]), "broker work root")
    config["_state_root"] = require_root_directory(Path(paths["state_root"]), "broker state root")
    output_root = Path(paths["allowed_output_root"])
    if output_root.is_symlink() or not output_root.is_dir():
        fail("allowed output root must be an existing non-symlink directory")
    config["_allowed_output_root"] = output_root.resolve()
    config["_broker"] = require_fixed_executable(
        Path(paths["broker"]), identities["broker_sha256"], "evaluation broker"
    )
    config["_core"] = require_fixed_file(
        Path(paths["core"]), identities["core_sha256"], "evaluation contract core"
    )
    config["_evaluator"] = require_fixed_executable(
        Path(paths["evaluator"]), identities["evaluator_sha256"], "external evaluator"
    )
    config["_sandbox_adapter"] = require_fixed_executable(
        Path(paths["sandbox_adapter"]),
        identities["sandbox_adapter_sha256"],
        "CPA sandbox adapter",
    )
    config["_docker_sandbox"] = require_fixed_executable(
        Path(paths["docker_sandbox"]),
        identities["docker_sandbox_sha256"],
        "Docker locality verifier",
    )
    if config["_broker"] != Path(__file__).resolve():
        fail("broker is not executing from the root-pinned fixed path")
    if config["_core"] != Path(core_module.__file__).resolve():
        fail("broker imported an unpinned evaluation contract core")
    for key, label in (
        ("sandbox_adapter_config", "sandbox adapter configuration"),
        ("age", "age executable"),
        ("openssl", "OpenSSL executable"),
        ("gh", "GitHub CLI executable"),
    ):
        candidate = Path(paths[key])
        if key == "sandbox_adapter_config":
            require_root_owned_regular(candidate, label, mode_mask=0o077)
        else:
            require_root_owned_regular(candidate, label, mode_mask=0o022)
            if not os.access(candidate, os.X_OK):
                fail(f"{label} is not executable")
        config[f"_{key}"] = candidate.resolve()
    for raw, label in (
        (github["token_file"], "root GitHub token"),
        (signing["private_key"], "evaluator private key"),
        (signing["public_key"], "evaluator public key"),
        (corpus["encrypted_bundle"], "encrypted independent corpus"),
        (corpus["age_identity"], "age identity"),
        (corpus["author_public_key"], "corpus author public key"),
    ):
        require_root_owned_regular(Path(raw), label, mode_mask=0o077 if "public" not in label else 0o022)
    validate_signing_key_material(
        Path(signing["private_key"]),
        Path(signing["public_key"]),
        Path(corpus["author_public_key"]),
        openssl=str(config["_openssl"]),
    )
    if sha256_file(Path(corpus["encrypted_bundle"])) != corpus["encrypted_bundle_sha256"]:
        fail("encrypted independent corpus differs from the root-pinned SHA-256")
    adapter_config_path = Path(paths["sandbox_adapter_config"])
    adapter_config_sha256 = sha256_file(adapter_config_path)
    if adapter_config_sha256 != identities["sandbox_adapter_config_sha256"]:
        fail("sandbox adapter configuration differs from the root-pinned SHA-256")
    adapter_config = exact_object(
        load_json(adapter_config_path, "sandbox adapter configuration", maximum=262_144),
        {
            "schema",
            "docker_executable",
            "docker_sandbox",
            "docker_sandbox_sha256",
            "sandbox_id",
            "daemon_id",
            "probe_image_id",
            "cpa_image_id",
            "counted_mock_image_id",
            "model",
            "scan_limit_bytes",
        },
        "sandbox adapter configuration",
    )
    require_literal(adapter_config["schema"], ADAPTER_CONFIG_SCHEMA, "adapter config schema")
    expected_adapter = {
        "docker_sandbox": str(config["_docker_sandbox"]),
        "docker_sandbox_sha256": identities["docker_sandbox_sha256"],
        "sandbox_id": sandbox["sandbox_id"],
        "daemon_id": sandbox["daemon_id"],
        "probe_image_id": sandbox["probe_image_id"],
        "cpa_image_id": sandbox["cpa_image_id"],
        "counted_mock_image_id": sandbox["counted_mock_image_id"],
        "model": sandbox["model"],
        "scan_limit_bytes": sandbox["scan_limit_bytes"],
    }
    for key, expected in expected_adapter.items():
        if adapter_config.get(key) != expected:
            fail(f"sandbox adapter configuration differs at {key}")
    docker_path = Path(adapter_config.get("docker_executable", ""))
    require_root_owned_regular(docker_path, "sandbox adapter Docker executable", mode_mask=0o022)
    if not os.access(docker_path, os.X_OK):
        fail("sandbox adapter Docker executable is not executable")
    config["_sandbox_adapter_config_sha256"] = adapter_config_sha256
    return config


class GitHubClient:
    def __init__(self, api_url: str, token: str):
        if api_url.rstrip("/") != "https://api.github.com":
            fail("GitHub API URL must be exactly https://api.github.com")
        self.api_url = api_url.rstrip("/")
        self.token = token
        self._api_opener = _no_redirect_opener(use_environment_proxy=True)
        self._artifact_opener = _no_redirect_opener(use_environment_proxy=True)

    def _request(
        self,
        method: str,
        endpoint: str,
        payload: Any | None = None,
        *,
        accept: str = "application/vnd.github+json",
        allow_not_found: bool = False,
        allowed_statuses: set[int] | None = None,
    ) -> tuple[int, bytes, Any]:
        data = None if payload is None else canonical_bytes(payload)
        headers = {
            "Accept": accept,
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "cag-round9-external-evaluation-broker/1",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        operation = request.Request(
            self.api_url + "/" + endpoint.lstrip("/"),
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self._api_opener.open(operation, timeout=60) as response:
                raw = response.read(268_435_457)
                status = response.status
                response_headers = response.headers
        except error.HTTPError as exc:
            try:
                raw = exc.read(1_048_577)
                status = exc.code
                response_headers = exc.headers
            finally:
                exc.close()
            if not (
                (allow_not_found and status == 404)
                or (allowed_statuses is not None and status in allowed_statuses)
            ):
                fail(f"GitHub API {method} {endpoint} failed with HTTP {status}")
        except (error.URLError, TimeoutError, OSError) as exc:
            raise ContractError("GitHub API request failed") from exc
        if len(raw) > 268_435_456:
            fail("GitHub API response exceeds the reviewed bound")
        if 300 <= status < 400 and not (allowed_statuses and status in allowed_statuses):
            fail("GitHub API redirect was rejected")
        return status, raw, response_headers

    def json(self, method: str, endpoint: str, payload: Any | None = None) -> dict[str, Any]:
        status, raw, _headers = self._request(method, endpoint, payload)
        if not 200 <= status < 300:
            fail("GitHub API JSON request failed")
        value = load_json_bytes(raw, "GitHub API response")
        if not isinstance(value, dict):
            fail("GitHub API response must be an object")
        return value

    def bytes(self, endpoint: str) -> bytes:
        status, _raw, headers = self._request(
            "GET",
            endpoint,
            accept="application/octet-stream",
            allowed_statuses={302, 303, 307, 308},
        )
        if status not in {302, 303, 307, 308}:
            fail("GitHub artifact API did not return the required storage redirect")
        location = headers.get("Location") if headers is not None else None
        if (
            not isinstance(location, str)
            or re.fullmatch(r"[\x21-\x7e]{1,8192}", location) is None
            or "\\" in location
        ):
            fail("GitHub artifact redirect Location is invalid")
        target = parse.urlsplit(location)
        if (
            target.scheme != "https"
            or not target.hostname
            or target.username is not None
            or target.password is not None
            or target.fragment
            or target.port not in (None, 443)
        ):
            fail("GitHub artifact redirect must be an uncredentialed HTTPS URL")
        operation = request.Request(
            location,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": "cag-round9-external-evaluation-broker/1",
            },
            method="GET",
        )
        try:
            with self._artifact_opener.open(operation, timeout=60) as response:
                if response.status != 200:
                    fail("GitHub artifact storage returned a non-success status")
                raw = response.read(268_435_457)
        except error.HTTPError as exc:
            try:
                status = exc.code
            finally:
                exc.close()
            fail(f"GitHub artifact storage failed with HTTP {status}")
        except (error.URLError, TimeoutError, OSError) as exc:
            raise ContractError("GitHub artifact storage request failed") from exc
        if len(raw) > 268_435_456:
            fail("GitHub artifact response exceeds the reviewed bound")
        return raw

    def ref(self, repository: str, full_ref: str, *, absent_ok: bool = False) -> dict[str, Any] | None:
        if not full_ref.startswith("refs/"):
            fail("Git reference must be fully qualified")
        name = parse.quote(full_ref[5:], safe="/")
        status, raw, _headers = self._request(
            "GET", f"repos/{repository}/git/ref/{name}", allow_not_found=absent_ok
        )
        if status == 404 and absent_ok:
            return None
        value = load_json_bytes(raw, "Git reference")
        if not isinstance(value, dict):
            fail("Git reference response must be an object")
        return value

    def tag(self, repository: str, tag_sha: str) -> dict[str, Any]:
        return self.json("GET", f"repos/{repository}/git/tags/{tag_sha}")

    def create_tagged_ref(
        self,
        repository: str,
        full_ref: str,
        target_commit: str,
        message: str,
    ) -> str:
        if not full_ref.startswith("refs/tags/"):
            fail("ledger reference must be a tag")
        tag_name = full_ref[len("refs/tags/") :]
        tag = self.json(
            "POST",
            f"repos/{repository}/git/tags",
            {"tag": tag_name, "message": message, "object": target_commit, "type": "commit"},
        )
        tag_sha = require_pattern(tag.get("sha"), HEX40, "created ledger tag object")
        try:
            self.json(
                "POST",
                f"repos/{repository}/git/refs",
                {"ref": full_ref, "sha": tag_sha},
            )
        except ContractError as original:
            # GitHub may commit create-ref and then lose the HTTP response. The
            # only safe recovery is an authenticated read-back of this exact
            # immutable tag object; a different or missing ref remains failure.
            recovered = self.ref(repository, full_ref, absent_ok=True)
            if recovered is None:
                raise original
            target = recovered.get("object")
            if not isinstance(target, dict) or target.get("type") != "tag" or target.get("sha") != tag_sha:
                fail("ledger reference recovery found a different tag object")
        return tag_sha


def verify_ledger_ruleset(client: GitHubClient, config: dict[str, Any]) -> None:
    github = config["github"]
    repository = config["repository"]
    ruleset = client.json(
        "GET", f"repos/{repository}/rulesets/{github['ledger_ruleset_id']}"
    )
    if (
        ruleset.get("id") != github["ledger_ruleset_id"]
        or ruleset.get("name") != github["ledger_ruleset_name"]
        or ruleset.get("target") != "tag"
        or ruleset.get("enforcement") != "active"
        or ruleset.get("bypass_actors") != []
    ):
        fail("ledger tag ruleset identity/enforcement differs")
    conditions = ruleset.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    includes = ref_name.get("include") if isinstance(ref_name, dict) else None
    excludes = ref_name.get("exclude") if isinstance(ref_name, dict) else None
    if not isinstance(includes, list) or not any(
        item in {"~ALL", "refs/tags/round9-eval-ledger/**", "refs/tags/round9-eval-ledger/**/*"}
        for item in includes
    ):
        fail("ledger tag ruleset does not cover the Round 9 namespace")
    if excludes != []:
        fail("ledger tag ruleset must not exclude any protected ledger reference")
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or not all(
        isinstance(item, dict)
        and isinstance(item.get("type"), str)
        and bool(item["type"])
        for item in rules
    ):
        fail("ledger tag ruleset contains malformed rule entries")
    types = {item["type"] for item in rules}
    if not {"deletion", "update"}.issubset(types):
        fail("ledger tag ruleset must prohibit deletion and update")


def validate_dispatch(args: argparse.Namespace, repository: str) -> None:
    if args.repository != repository:
        fail("workflow repository differs from root-owned broker configuration")
    require_pattern(args.repository, REPOSITORY, "workflow repository")
    require_literal(args.tag, TAG, "candidate tag")
    require_pattern(args.tag_object_sha, HEX40, "candidate tag object")
    require_pattern(args.commit, HEX40, "candidate commit")
    require_pattern(args.tree, HEX40, "candidate tree")
    require_literal(args.dispatch_ref, f"refs/tags/{TAG}", "workflow dispatch ref")
    require_literal(args.dispatch_sha, args.commit, "workflow dispatch SHA")
    require_literal(
        args.workflow_ref,
        f"{repository}/{HOST_WORKFLOW}@refs/tags/{TAG}",
        "workflow source ref",
    )
    require_literal(args.workflow_sha, args.commit, "workflow source SHA")
    for name in (
        "phase1_run_id",
        "phase1_run_attempt",
        "phase1_artifact_id",
        "workflow_run_id",
        "workflow_run_attempt",
    ):
        exact_int(getattr(args, name), name, minimum=1)
    require_pattern(args.phase1_artifact_digest, SHA256_DIGEST, "Phase 1 artifact digest")
    require_pattern(args.challenge, HEX64, "workflow challenge")
    require_pattern(args.so_sha256, HEX64, "candidate SO SHA-256")
    require_pattern(
        args.classifier_policy_version, IDENTIFIER, "candidate classifier policy version"
    )
    if not args.classifier_policy_version.startswith("classifier-policy-v8"):
        fail("candidate classifier policy is not a Round 9 v8 identity")
    require_pattern(
        args.classifier_policy_sha256, HEX64, "candidate classifier policy SHA-256"
    )
    require_literal(args.ruleset_version, "1.0.10", "candidate ruleset version")
    for name in (
        "ruleset_sha256",
        "ruleset_manifest_sha256",
        "build_metadata_sha256",
        "release_manifest_sha256",
    ):
        require_pattern(getattr(args, name), HEX64, name.replace("_", " "))


def verify_remote_identity(
    client: GitHubClient,
    args: argparse.Namespace,
    *,
    require_failed_host_run: bool = False,
) -> None:
    repository = args.repository
    main = client.ref(repository, "refs/heads/main")
    if main is None or main.get("object", {}).get("sha") != args.commit:
        fail("candidate commit is not exact remote main")
    tag_ref = client.ref(repository, f"refs/tags/{args.tag}")
    if tag_ref is None or tag_ref.get("object", {}).get("type") != "tag" or tag_ref["object"].get("sha") != args.tag_object_sha:
        fail("candidate annotated tag reference differs")
    tag = client.tag(repository, args.tag_object_sha)
    if tag.get("object", {}).get("type") != "commit" or tag["object"].get("sha") != args.commit:
        fail("candidate annotated tag object differs")
    commit = client.json("GET", f"repos/{repository}/git/commits/{args.commit}")
    if commit.get("tree", {}).get("sha") != args.tree:
        fail("candidate tree differs")
    host_run = client.json("GET", f"repos/{repository}/actions/runs/{args.workflow_run_id}")
    host_run_active = (
        host_run.get("status") in {"queued", "in_progress"}
        and host_run.get("conclusion") is None
    )
    host_run_recoverable = (
        host_run.get("status") == "completed"
        and host_run.get("conclusion")
        in {"action_required", "cancelled", "failure", "stale", "startup_failure", "timed_out"}
    )
    host_run_state_valid = host_run_recoverable if require_failed_host_run else host_run_active
    if not (
        host_run.get("id") == args.workflow_run_id
        and host_run.get("run_attempt") == args.workflow_run_attempt
        and host_run.get("name") == HOST_WORKFLOW_NAME
        and host_run.get("path") == HOST_WORKFLOW
        and host_run.get("event") == "workflow_dispatch"
        and host_run.get("head_sha") == args.commit
        and host_run_state_valid
        and host_run.get("repository", {}).get("full_name") == repository
    ):
        fail("Host workflow run identity differs")
    run = client.json("GET", f"repos/{repository}/actions/runs/{args.phase1_run_id}")
    if not (
        run.get("id") == args.phase1_run_id
        and run.get("run_attempt") == args.phase1_run_attempt
        and run.get("name") == PHASE1_WORKFLOW_NAME
        and run.get("path") == RELEASE_WORKFLOW
        and run.get("event") == "workflow_dispatch"
        and run.get("head_sha") == args.commit
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("repository", {}).get("full_name") == repository
    ):
        fail("Phase 1 workflow run identity differs")
    artifact = client.json(
        "GET", f"repos/{repository}/actions/artifacts/{args.phase1_artifact_id}"
    )
    expected_name = (
        f"round9-rc-{TAG}-{args.commit}-{args.phase1_run_id}-{args.phase1_run_attempt}"
    )
    if not (
        artifact.get("id") == args.phase1_artifact_id
        and artifact.get("name") == expected_name
        and artifact.get("digest") == args.phase1_artifact_digest
        and artifact.get("expired") is False
        and artifact.get("workflow_run", {}).get("id") == args.phase1_run_id
    ):
        fail("Phase 1 artifact metadata differs")


def safe_extract_zip(raw: bytes, output: Path) -> None:
    archive_path = output.parent / "phase1.zip"
    archive_path.write_bytes(raw)
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)) or set(names) != ARTIFACT_NAMES:
            fail("Phase 1 artifact ZIP entries are not the exact 17 assets")
        if sum(item.file_size for item in infos) > 1_073_741_824:
            fail("Phase 1 artifact ZIP expands beyond the reviewed bound")
        for info in infos:
            path = PurePosixPath(info.filename)
            unix_mode = info.external_attr >> 16
            if (
                path.is_absolute()
                or ".." in path.parts
                or len(path.parts) != 1
                or info.is_dir()
                or info.file_size > 536_870_912
                or unix_mode & 0o170000 == 0o120000
            ):
                fail("Phase 1 artifact ZIP contains an unsafe entry")
            target = output / info.filename
            with archive.open(info, "r") as source, target.open("xb") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)
            os.chmod(target, 0o600)


def safe_extract_public_development_corpus(
    archive_path: Path,
    output: Path,
    public_evidence: dict[str, Any],
) -> dict[str, Any]:
    """Extract only manifest-bound public text bytes from the attested source tar.

    No source file outside the selected public corpus is opened, and no archive
    entry is executed.  The full archive namespace is still checked so a
    traversal, duplicate, link, special file, or prefix drift fails closed.
    """

    if output.exists() or output.is_symlink():
        fail("public development extraction output must be absent")
    source_info = archive_path.lstat()
    if not archive_path.is_file() or archive_path.is_symlink() or source_info.st_size > 536_870_912:
        fail("Phase 1 source archive is not a bounded regular file")
    name = public_evidence.get("name")
    if (
        not isinstance(name, str)
        or re.fullmatch(r"round9-public-adversarial-v[1-9][0-9]*", name) is None
    ):
        fail("public development evidence corpus name is invalid")
    manifest_binding = exact_object(
        public_evidence.get("manifest"),
        {"bytes", "sha256"},
        "public development manifest binding",
    )
    manifest_size = exact_int(
        manifest_binding["bytes"], "public development manifest bytes", minimum=1
    )
    if manifest_size > 1_048_576:
        fail("public development manifest exceeds the reviewed bound")
    manifest_sha256 = require_pattern(
        manifest_binding["sha256"], HEX64, "public development manifest sha256"
    )
    archive_prefix = f"cyber-abuse-guard-v{TAG.removeprefix('v')}/"
    corpus_prefix = archive_prefix + f"testdata/{name}/"

    def normalized_member_name(member: tarfile.TarInfo) -> str:
        raw_name = member.name
        if not raw_name or "\\" in raw_name or "\x00" in raw_name:
            fail("Phase 1 source archive contains an invalid path")
        stripped = raw_name.rstrip("/")
        path = PurePosixPath(stripped)
        if (
            path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or str(path) != stripped
            or not stripped.startswith(archive_prefix.rstrip("/") + "/")
            and stripped != archive_prefix.rstrip("/")
        ):
            fail("Phase 1 source archive contains an entry outside its fixed prefix")
        return stripped

    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > 20_000:
                fail("Phase 1 source archive member count is outside the reviewed bound")
            normalized: dict[str, tarfile.TarInfo] = {}
            expanded = 0
            for member in members:
                member_name = normalized_member_name(member)
                if member_name in normalized:
                    fail("Phase 1 source archive contains duplicate normalized paths")
                normalized[member_name] = member
                if not (member.isfile() or member.isdir()):
                    fail("Phase 1 source archive contains a link or special file")
                if member.size < 0 or member.size > 134_217_728:
                    fail("Phase 1 source archive member exceeds the reviewed bound")
                expanded += member.size
                if expanded > 536_870_912:
                    fail("Phase 1 source archive expands beyond the reviewed bound")

            manifest_name = corpus_prefix + "manifest.json"
            manifest_member = normalized.get(manifest_name)
            if manifest_member is None or not manifest_member.isfile() or manifest_member.size != manifest_size:
                fail("Phase 1 source archive lacks the exact public manifest")

            def read_member(member: tarfile.TarInfo, maximum: int, label: str) -> bytes:
                if not member.isfile() or member.size <= 0 or member.size > maximum:
                    fail(f"{label} size or type is outside the reviewed bound")
                source = archive.extractfile(member)
                if source is None:
                    fail(f"{label} could not be opened")
                with source:
                    raw = source.read(maximum + 1)
                if len(raw) != member.size or len(raw) > maximum:
                    fail(f"{label} changed size while being read")
                return raw

            manifest_raw = read_member(manifest_member, 1_048_576, "public manifest")
            if sha256_bytes(manifest_raw) != manifest_sha256:
                fail("Phase 1 source archive public manifest digest differs")
            manifest = load_json_bytes(manifest_raw, "public development manifest")
            payload_rows = manifest.get("payloads") if isinstance(manifest, dict) else None
            if not isinstance(payload_rows, list) or not payload_rows or len(payload_rows) > 256:
                fail("public development manifest payload list is invalid")
            encoded_files: list[str] = []
            for index, payload in enumerate(payload_rows):
                encoded = payload.get("encoded_file") if isinstance(payload, dict) else None
                if (
                    not isinstance(encoded, str)
                    or re.fullmatch(r"payloads/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.b64", encoded)
                    is None
                    or encoded in encoded_files
                ):
                    fail(f"public development payload {index} encoded path is invalid")
                encoded_files.append(encoded)
            allowed_under_corpus = {
                corpus_prefix.rstrip("/"),
                corpus_prefix + "README.md",
                manifest_name,
                corpus_prefix + "payloads",
                *(corpus_prefix + encoded for encoded in encoded_files),
            }
            observed_under_corpus = {
                member_name
                for member_name in normalized
                if member_name == corpus_prefix.rstrip("/")
                or member_name.startswith(corpus_prefix)
            }
            if observed_under_corpus != allowed_under_corpus:
                fail("Phase 1 source archive public corpus contains an extra or missing entry")

            output.mkdir(mode=0o700)
            payload_output = output / "payloads"
            payload_output.mkdir(mode=0o700)
            atomic_write(output / "manifest.json", manifest_raw, mode=0o400)
            for encoded in encoded_files:
                member_name = corpus_prefix + encoded
                member = normalized.get(member_name)
                if member is None:
                    fail("Phase 1 source archive lacks a manifest-listed public payload")
                decoded_bytes = next(
                    row.get("decoded_bytes")
                    for row in payload_rows
                    if isinstance(row, dict) and row.get("encoded_file") == encoded
                )
                decoded_size = exact_int(
                    decoded_bytes, f"public payload {encoded} decoded bytes", minimum=1
                )
                maximum_encoded = ((decoded_size + 2) // 3) * 4 + 1
                encoded_raw = read_member(member, maximum_encoded, f"public payload {encoded}")
                target = output.joinpath(*PurePosixPath(encoded).parts)
                atomic_write(target, encoded_raw, mode=0o400)
    except (tarfile.TarError, OSError) as exc:
        raise ContractError("Phase 1 source archive could not be safely inspected") from exc

    identity, cases = load_public_counted_mock_corpus(output, public_evidence)
    if not cases:
        fail("public development corpus contains no §13.25 cases")
    return identity


def sidecar_digest(path: Path, target_name: str) -> str:
    raw = path.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ContractError("SHA-256 sidecar is not ASCII") from exc
    parts = text.rstrip("\n").split("  ")
    if len(parts) != 2 or parts[1] != target_name:
        fail("SHA-256 sidecar target differs")
    return require_pattern(parts[0], HEX64, "SHA-256 sidecar digest")


def validate_phase1_build_metadata(value: Any, args: argparse.Namespace) -> dict[str, Any]:
    metadata = exact_object(
        value,
        {
            "schema_version",
            "version",
            "source_version",
            "commit",
            "tree",
            "ruleset_version",
            "ruleset_sha256",
            "classifier_policy_version",
            "classifier_policy_sha256",
            "streaming_scanner",
            "dirty",
            "source_date_epoch",
            "go_version",
            "goos",
            "goarch",
            "cgo_enabled",
            "cc_command",
            "gcc_version",
            "gcc_target",
            "binutils_ld_version",
            "glibc_version",
            "builder_image",
            "builder_image_digest",
            "builder_reference",
            "runner_label",
            "runner_os",
            "runner_arch",
            "runner_environment",
            "runner_name",
            "runner_image_os",
            "runner_image_version",
        },
        "Phase 1 build metadata",
    )
    expected = {
        "schema_version": 4,
        "version": "0.16-rc.3",
        "source_version": "0.16",
        "commit": args.commit,
        "tree": args.tree,
        "ruleset_version": args.ruleset_version,
        "ruleset_sha256": args.ruleset_sha256,
        "classifier_policy_version": args.classifier_policy_version,
        "classifier_policy_sha256": args.classifier_policy_sha256,
        "dirty": False,
        "go_version": "go1.26.4",
        "goos": "linux",
        "goarch": "amd64",
        "cgo_enabled": True,
        "cc_command": "gcc",
        "gcc_target": "x86_64-linux-gnu",
    }
    for key, expected_value in expected.items():
        if metadata.get(key) != expected_value:
            fail(f"Phase 1 build metadata differs at {key}")
    exact_int(metadata["source_date_epoch"], "Phase 1 source date epoch", minimum=1)
    require_pattern(metadata["streaming_scanner"], IDENTIFIER, "streaming scanner identity")
    require_pattern(metadata["builder_image_digest"], SHA256_DIGEST, "builder image digest")
    if metadata["builder_reference"] != metadata["builder_image"] + "@" + metadata["builder_image_digest"]:
        fail("Phase 1 builder image reference is not digest-pinned")
    for key in (
        "gcc_version",
        "binutils_ld_version",
        "glibc_version",
        "runner_label",
        "runner_os",
        "runner_arch",
        "runner_environment",
        "runner_name",
        "runner_image_os",
        "runner_image_version",
    ):
        if not isinstance(metadata[key], str) or not metadata[key]:
            fail(f"Phase 1 build metadata {key} is empty")
    return metadata


def validate_phase1_ruleset_manifest(value: Any, args: argparse.Namespace) -> dict[str, Any]:
    manifest = exact_object(
        value,
        {"schema_version", "plugin_version", "ruleset_version", "ruleset_sha256", "files"},
        "Phase 1 ruleset manifest",
    )
    expected = {
        "schema_version": 1,
        "plugin_version": "0.16-rc.3",
        "ruleset_version": args.ruleset_version,
        "ruleset_sha256": args.ruleset_sha256,
    }
    for key, expected_value in expected.items():
        if manifest.get(key) != expected_value:
            fail(f"Phase 1 ruleset manifest differs at {key}")
    files = manifest["files"]
    if not isinstance(files, list) or len(files) != len(RULESET_PATHS):
        fail("Phase 1 ruleset manifest file list is invalid")
    observed: set[str] = set()
    for index, item in enumerate(files):
        row = exact_object(item, {"path", "sha256"}, f"ruleset file {index}")
        if row["path"] in observed or row["path"] not in RULESET_PATHS:
            fail("Phase 1 ruleset manifest path set differs")
        observed.add(row["path"])
        require_pattern(row["sha256"], HEX64, f"ruleset file {row['path']} SHA-256")
    if observed != RULESET_PATHS:
        fail("Phase 1 ruleset manifest path set differs")
    return manifest


def validate_phase1_release_manifest(
    value: Any,
    args: argparse.Namespace,
    *,
    so_sha256: str,
    build_metadata_sha256: str,
    ruleset_manifest_sha256: str,
) -> dict[str, Any]:
    manifest = exact_object(
        value,
        {
            "schema_version",
            "release_phase",
            "publish_rc_release",
            "status",
            "packaging_profile",
            "source_version",
            "artifact_version",
            "tag",
            "tag_object",
            "commit",
            "tree",
            "source_date_epoch",
            "ci_run_id",
            "ci_run_attempt",
            "artifact_count",
            "cpa",
            "production_validation",
            "independent_audit",
            "independent_audit_requirement",
            "independent_evaluation",
            "independent_evaluation_requirement",
            "workflow",
            "artifacts",
            "round9",
        },
        "Phase 1 release manifest",
    )
    expected = {
        "schema_version": 6,
        "release_phase": "candidate",
        "publish_rc_release": False,
        "source_version": "0.16",
        "artifact_version": "0.16-rc.3",
        "tag": TAG,
        "tag_object": args.tag_object_sha,
        "commit": args.commit,
        "tree": args.tree,
        "ci_run_id": args.phase1_run_id,
        "ci_run_attempt": args.phase1_run_attempt,
        "artifact_count": len(ARTIFACT_NAMES),
        "production_validation": "NOT_RUN / PROHIBITED",
        "independent_audit": "NOT_PROVIDED",
        "independent_audit_requirement": "required",
        "independent_evaluation": "NOT_PROVIDED",
        "independent_evaluation_requirement": "required",
    }
    for key, expected_value in expected.items():
        if manifest.get(key) != expected_value:
            fail(f"Phase 1 release manifest differs at {key}")
    exact_int(manifest["source_date_epoch"], "release manifest source date epoch", minimum=1)
    cpa = exact_object(
        manifest["cpa"],
        {
            "primary",
            "external_evaluation_validation",
            "external_evaluation_origin",
            "external_evaluation_claim",
            "real_provider_validation",
        },
        "release manifest CPA identity",
    )
    primary = exact_object(
        cpa["primary"],
        {"version", "commit", "source_compatibility", "counted_mock_validation"},
        "release manifest primary CPA",
    )
    if primary != {
        "version": "v7.2.95",
        "commit": "f71ec0eb6776854457892452cf28c47f0d658251",
        "source_compatibility": "PASS",
        "counted_mock_validation": "NOT_RUN / EXTERNAL_EVALUATION_REQUIRED",
    }:
        fail("Phase 1 release manifest CPA identity differs")
    if (
        cpa["external_evaluation_validation"]
        != "NOT_RUN / EXTERNAL_EVALUATION_REQUIRED"
        or cpa["external_evaluation_origin"]
        != "NOT_PROVIDED / EXTERNAL_EVALUATION_REQUIRED"
        or cpa["external_evaluation_claim"]
        != "NOT_RUN / EXTERNAL_EVALUATION_REQUIRED"
        or cpa["real_provider_validation"] != "NOT_RUN / PROHIBITED"
    ):
        fail("Phase 1 release manifest external-evaluation boundary differs")
    workflow = exact_object(
        manifest["workflow"],
        {"repository", "ref", "sha", "dispatch_ref", "run_id", "run_attempt"},
        "release manifest workflow",
    )
    if (
        workflow["repository"] != args.repository
        or workflow["sha"] != args.commit
        or workflow["run_id"] != args.phase1_run_id
        or workflow["run_attempt"] != args.phase1_run_attempt
    ):
        fail("Phase 1 release manifest workflow identity differs")
    artifacts = exact_object(
        manifest["artifacts"],
        {
            "so",
            "store_zip",
            "audit_bundle",
            "build_metadata_sha256",
            "checksums_sha256",
            "ruleset_manifest_sha256",
            "ruleset_sha256",
            "sbom_sha256",
            "test_summary",
            "rc_evidence",
            "source_archive",
        },
        "release manifest artifacts",
    )
    so = exact_object(artifacts["so"], {"name", "sha256", "sidecar_sha256"}, "release SO")
    if so["name"] != SO_NAME or so["sha256"] != so_sha256:
        fail("Phase 1 release manifest SO identity differs")
    if artifacts["build_metadata_sha256"] != build_metadata_sha256:
        fail("Phase 1 release manifest build metadata digest differs")
    if artifacts["ruleset_manifest_sha256"] != ruleset_manifest_sha256:
        fail("Phase 1 release manifest ruleset manifest digest differs")
    round9 = exact_object(
        manifest["round9"],
        {
            "release_lane",
            "classifier",
            "ruleset",
            "corpus_contract_status",
            "corpus",
            "audit_contract",
            "machine_reports",
            "development_evidence",
            "counted_mock",
            "external_evaluation",
            "external_ledger_proof",
            "release",
            "cpa_contract",
        },
        "release manifest Round 9 identity",
    )
    if round9["release_lane"] != "round9" or round9["classifier"] != {
        "version": args.classifier_policy_version,
        "sha256": args.classifier_policy_sha256,
    } or round9["ruleset"] != {
        "version": args.ruleset_version,
        "sha256": args.ruleset_sha256,
    }:
        fail("Phase 1 release manifest policy/ruleset identity differs")
    development = validate_development_evidence(round9["development_evidence"])
    expected_development_candidate = {
        "tag": TAG,
        "tag_object_sha": args.tag_object_sha,
        "commit": args.commit,
        "tree": args.tree,
        "classifier": {
            "version": args.classifier_policy_version,
            "sha256": args.classifier_policy_sha256,
        },
        "ruleset": {
            "version": args.ruleset_version,
            "sha256": args.ruleset_sha256,
        },
    }
    if development["candidate"] != expected_development_candidate:
        fail("Phase 1 development evidence candidate identity differs")
    not_provided = {
        "state": "NOT_PROVIDED",
        "reason": "EXTERNAL_EVALUATION_REQUIRED",
    }
    expected_corpus = dict(development["corpus"])
    expected_corpus.update(
        {
            "independent_benign": not_provided,
            "independent_malicious": not_provided,
        }
    )
    if (
        round9["corpus_contract_status"] != "PASS"
        or round9["corpus"] != expected_corpus
        or round9["audit_contract"] != development["audit_contract"]
        or round9["machine_reports"] != development["machine_reports"]
        or round9["counted_mock"] != not_provided
        or round9["external_evaluation"] != not_provided
        or round9["external_ledger_proof"] != not_provided
    ):
        fail("Phase 1 release manifest Round 9 evidence boundary differs")
    release = exact_object(
        round9["release"],
        {"tag", "title", "body", "publication_permitted", "draft", "prerelease", "latest", "asset_allowlist"},
        "release manifest Round 9 release",
    )
    if (
        release["tag"] != TAG
        or release["publication_permitted"] is not False
        or release["draft"] is not False
        or release["prerelease"] is not True
        or release["latest"] is not False
        or set(release["asset_allowlist"]) != ARTIFACT_NAMES
        or len(release["asset_allowlist"]) != len(ARTIFACT_NAMES)
    ):
        fail("Phase 1 release manifest release contract differs")
    cpa_contract = exact_object(
        round9["cpa_contract"],
        {"version", "commit", "upstream_version_policy"},
        "release manifest Round 9 CPA contract",
    )
    if cpa_contract != {
        "version": "v7.2.95",
        "commit": "f71ec0eb6776854457892452cf28c47f0d658251",
        "upstream_version_policy": "fixed-no-automatic-follow",
    }:
        fail("Phase 1 release manifest Round 9 CPA contract differs")
    return manifest


def verify_phase1_assets(
    client: GitHubClient,
    config: dict[str, Any],
    args: argparse.Namespace,
    output: Path,
) -> tuple[Path, dict[str, str], dict[str, Any]]:
    raw = client.bytes(
        f"repos/{args.repository}/actions/artifacts/{args.phase1_artifact_id}/zip"
    )
    if "sha256:" + sha256_bytes(raw) != args.phase1_artifact_digest:
        fail("downloaded Phase 1 artifact digest differs")
    output.mkdir(mode=0o700)
    safe_extract_zip(raw, output)
    so = output / SO_NAME
    so_sha = sha256_file(so)
    if sidecar_digest(output / f"{SO_NAME}.sha256", SO_NAME) != so_sha:
        fail("candidate SO sidecar differs")
    if so_sha != args.so_sha256:
        fail("candidate SO differs from the dispatched public identity")
    checksums: dict[str, str] = {}
    for line in (output / "checksums.txt").read_text(encoding="ascii").splitlines():
        parts = line.split("  ")
        if len(parts) != 2 or parts[1] in checksums:
            fail("Phase 1 checksums file is invalid")
        checksums[parts[1]] = require_pattern(parts[0], HEX64, "Phase 1 checksum")
    for name in ARTIFACT_NAMES - {"checksums.txt"}:
        if checksums.get(name) != sha256_file(output / name):
            fail(f"Phase 1 checksum differs for {name}")
    build_metadata_path = output / "build-metadata.json"
    ruleset_manifest_path = output / "ruleset-manifest.json"
    release_manifest_path = output / "rc-release-manifest.json"
    build_metadata_sha256 = sha256_file(build_metadata_path)
    ruleset_manifest_sha256 = sha256_file(ruleset_manifest_path)
    release_manifest_sha256 = sha256_file(release_manifest_path)
    if build_metadata_sha256 != args.build_metadata_sha256:
        fail("Phase 1 build metadata file digest differs")
    if ruleset_manifest_sha256 != args.ruleset_manifest_sha256:
        fail("Phase 1 ruleset manifest file digest differs")
    if release_manifest_sha256 != args.release_manifest_sha256:
        fail("Phase 1 release manifest file digest differs")
    validate_phase1_build_metadata(
        load_json(build_metadata_path, "Phase 1 build metadata"), args
    )
    validate_phase1_ruleset_manifest(
        load_json(ruleset_manifest_path, "Phase 1 ruleset manifest"), args
    )
    if sidecar_digest(output / "ruleset.sha256", "ruleset-manifest.json") != ruleset_manifest_sha256:
        fail("Phase 1 ruleset sidecar differs")
    if sidecar_digest(
        output / "rc-release-manifest.json.sha256", "rc-release-manifest.json"
    ) != release_manifest_sha256:
        fail("Phase 1 release manifest sidecar differs")
    release_manifest = validate_phase1_release_manifest(
        load_json(release_manifest_path, "Phase 1 release manifest"),
        args,
        so_sha256=so_sha,
        build_metadata_sha256=build_metadata_sha256,
        ruleset_manifest_sha256=ruleset_manifest_sha256,
    )

    token = read_secret(Path(config["github"]["token_file"]), "root GitHub token")
    environment = minimal_subprocess_env(
        home=str(config["_work_root"]), github_token=token
    )
    for name in sorted(ARTIFACT_NAMES):
        command = [
            str(config["_gh"]),
            "attestation",
            "verify",
            str(output / name),
            "--repo",
            args.repository,
            "--signer-workflow",
            f"{args.repository}/{RELEASE_WORKFLOW}",
            "--signer-digest",
            args.commit,
            "--source-ref",
            f"refs/tags/{TAG}",
            "--source-digest",
            args.commit,
        ]
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            check=False,
            timeout=120,
        )
        if completed.returncode != 0:
            fail(f"GitHub attestation verification failed for {name}")
    return so, {
        "so_sha256": so_sha,
        "classifier_policy_version": args.classifier_policy_version,
        "classifier_policy_sha256": args.classifier_policy_sha256,
        "ruleset_version": args.ruleset_version,
        "ruleset_sha256": args.ruleset_sha256,
        "ruleset_manifest_sha256": ruleset_manifest_sha256,
        "build_metadata_sha256": build_metadata_sha256,
        "release_manifest_sha256": release_manifest_sha256,
    }, release_manifest["round9"]["development_evidence"]


def safe_extract_corpus(archive_path: Path, output: Path) -> None:
    output.mkdir(mode=0o700)
    with tarfile.open(archive_path, mode="r:*") as archive:
        members = archive.getmembers()
        names = [item.name for item in members]
        if len(names) != len(set(names)) or set(names) != CORPUS_ARCHIVE_NAMES:
            fail("decrypted corpus archive entries are not exact")
        if sum(item.size for item in members) > 536_870_912:
            fail("decrypted corpus archive exceeds the reviewed bound")
        for member in members:
            path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or path.is_absolute()
                or ".." in path.parts
                or len(path.parts) != 1
                or member.size <= 0
                or member.size > 268_435_456
            ):
                fail("decrypted corpus archive contains an unsafe entry")
            source = archive.extractfile(member)
            if source is None:
                fail("decrypted corpus archive entry is unreadable")
            target = output / member.name
            with source, target.open("xb") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)
            os.chmod(target, 0o400)


def corpus_identity(config: dict[str, Any]) -> dict[str, Any]:
    corpus = config["corpus"]
    identities = config["identities"]
    return validate_corpus(
        {
            "evaluation_id": corpus["evaluation_id"],
            "bundle_sha256": corpus["encrypted_bundle_sha256"],
            "bundle_manifest_sha256": corpus["bundle_manifest_sha256"],
            "benign_manifest_sha256": corpus["benign_manifest_sha256"],
            "benign_cases_sha256": corpus["benign_cases_sha256"],
            "malicious_manifest_sha256": corpus["malicious_manifest_sha256"],
            "malicious_cases_sha256": corpus["malicious_cases_sha256"],
            "author_key_id": identities["author_key_id"],
            "plaintext_in_repository": False,
        }
    )


def evaluator_identity(config: dict[str, Any]) -> dict[str, Any]:
    identities = config["identities"]
    return validate_evaluator(
        {
            "version": identities["evaluator_version"],
            "sha256": identities["evaluator_sha256"],
            "core_sha256": identities["core_sha256"],
            "broker_sha256": identities["broker_sha256"],
            "key_id": identities["evaluator_key_id"],
            "execution_mode": "EXTERNAL_ROOT_OWNED_BLACK_BOX_CPA",
        }
    )


def candidate_identity(args: argparse.Namespace, assets: dict[str, str]) -> dict[str, Any]:
    return validate_candidate(
        {
            "tag": args.tag,
            "tag_object_sha": args.tag_object_sha,
            "source_version": "0.16",
            "commit": args.commit,
            "tree": args.tree,
            "so_sha256": assets["so_sha256"],
            "cpa_version": "v7.2.95",
            "cpa_commit": "f71ec0eb6776854457892452cf28c47f0d658251",
            "classifier_policy_version": assets["classifier_policy_version"],
            "classifier_policy_sha256": assets["classifier_policy_sha256"],
            "ruleset_version": assets["ruleset_version"],
            "ruleset_sha256": assets["ruleset_sha256"],
            "ruleset_manifest_sha256": assets["ruleset_manifest_sha256"],
            "build_metadata_sha256": assets["build_metadata_sha256"],
            "release_manifest_sha256": assets["release_manifest_sha256"],
            "phase1_run_id": args.phase1_run_id,
            "phase1_run_attempt": args.phase1_run_attempt,
            "phase1_artifact_id": args.phase1_artifact_id,
            "phase1_artifact_digest": args.phase1_artifact_digest,
        }
    )


def execution_identity(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    sandbox = config["sandbox"]
    return validate_execution(
        {
            "workflow_run_id": args.workflow_run_id,
            "workflow_run_attempt": args.workflow_run_attempt,
            "challenge_sha256": challenge_sha256(args.challenge),
            "route_order_seed_sha256": challenge_sha256(args.challenge),
            "sandbox_id": sandbox["sandbox_id"],
            "daemon_id": sandbox["daemon_id"],
            "probe_image_id": sandbox["probe_image_id"],
            "cpa_version": "v7.2.95",
            "cpa_commit": "f71ec0eb6776854457892452cf28c47f0d658251",
            "cpa_image_id": sandbox["cpa_image_id"],
            "counted_mock_image_id": sandbox["counted_mock_image_id"],
            "model": sandbox["model"],
            "scan_limit_bytes": sandbox["scan_limit_bytes"],
            "sandbox_adapter_sha256": config["identities"]["sandbox_adapter_sha256"],
            "sandbox_adapter_config_sha256": config["identities"][
                "sandbox_adapter_config_sha256"
            ],
            "docker_sandbox_sha256": config["identities"]["docker_sandbox_sha256"],
            "network_binding": dict(FIXED_NETWORK_BINDING),
            "phase_protocol": dict(FIXED_PHASE_PROTOCOL),
            "production_accessed": False,
            "real_provider_contacted": False,
        }
    )


def ledger_event_payload(
    event: str,
    *,
    repository: str,
    namespace: str,
    candidate: dict[str, Any],
    evaluator: dict[str, Any],
    corpus: dict[str, Any],
    execution: dict[str, Any],
    development_evidence: dict[str, Any],
    counted_mock: dict[str, Any] | None = None,
    public_counted_mock: dict[str, Any] | None = None,
    evaluation_digest: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": LEDGER_EVENT_SCHEMA,
        "event": event,
        "repository": repository,
        "namespace": namespace,
        "candidate": candidate,
        "evaluator": evaluator,
        "corpus": corpus,
        "execution": execution,
        "development_evidence": development_evidence,
        "counted_mock": counted_mock,
        "public_counted_mock": public_counted_mock,
        "evaluation_envelope_sha256": evaluation_digest,
    }


def load_ledger_entry(
    client: GitHubClient,
    repository: str,
    full_ref: str,
    expected_commit: str,
) -> dict[str, Any]:
    ref = client.ref(repository, full_ref)
    if ref is None or ref.get("object", {}).get("type") != "tag":
        fail(f"ledger reference is not an annotated tag: {full_ref}")
    tag_sha = require_pattern(ref["object"].get("sha"), HEX40, "ledger tag object")
    tag = client.tag(repository, tag_sha)
    if tag.get("object", {}).get("type") != "commit" or tag["object"].get("sha") != expected_commit:
        fail(f"ledger tag does not point to the candidate commit: {full_ref}")
    message = tag.get("message")
    if not isinstance(message, str):
        fail("ledger tag message is not text")
    envelope = load_json_bytes(message.encode("utf-8"), "ledger tag message")
    if not isinstance(envelope, dict) or canonical_bytes(envelope).decode("utf-8") != message:
        fail("ledger tag message is not canonical JSON")
    return {
        "ref": full_ref,
        "tag_object_sha": tag_sha,
        "message_sha256": sha256_bytes(message.encode("utf-8")),
        "envelope": envelope,
    }


def create_event(
    client: GitHubClient,
    config: dict[str, Any],
    event: str,
    payload: dict[str, Any],
    candidate_commit: str,
) -> str:
    envelope = signed_envelope(
        payload,
        Path(config["signing"]["private_key"]),
        config["identities"]["evaluator_key_id"],
        openssl=str(config["_openssl"]),
    )
    message = canonical_bytes(envelope).decode("utf-8")
    full_ref = ledger_ref(payload["namespace"], event)
    return client.create_tagged_ref(
        config["repository"], full_ref, candidate_commit, message
    )


def build_proof(
    client: GitHubClient,
    config: dict[str, Any],
    namespace: str,
    commit: str,
) -> dict[str, Any]:
    repository = config["repository"]
    aborted = client.ref(repository, ledger_ref(namespace, "aborted"), absent_ok=True)
    if aborted is not None:
        fail("ledger contains an aborted event")
    return {
        "schema": LEDGER_PROOF_SCHEMA,
        "repository": repository,
        "namespace": namespace,
        "refs": {
            event: load_ledger_entry(
                client, repository, ledger_ref(namespace, event), commit
            )
            for event in ("reserved", "started", "result")
        },
        "aborted_ref_absent": True,
    }


def validate_external_aggregate(
    aggregate_value: Any,
    config: dict[str, Any],
    candidate: dict[str, Any],
    corpus: dict[str, Any],
    execution: dict[str, Any],
) -> dict[str, Any]:
    aggregate = exact_object(
        aggregate_value,
        {
            "schema",
            "evaluator",
            "corpus",
            "sandbox",
            "metrics",
            "public_counted_mock",
            "privacy",
        },
        "external evaluator aggregate",
    )
    require_literal(
        aggregate["schema"], EVALUATOR_AGGREGATE_SCHEMA, "evaluator aggregate schema"
    )
    aggregate_evaluator = exact_object(
        aggregate["evaluator"],
        {"version", "sha256", "core_sha256", "execution_mode"},
        "aggregate evaluator",
    )
    if aggregate_evaluator != {
        "version": config["identities"]["evaluator_version"],
        "sha256": config["identities"]["evaluator_sha256"],
        "core_sha256": config["identities"]["core_sha256"],
        "execution_mode": "EXTERNAL_ROOT_OWNED_BLACK_BOX_CPA",
    }:
        fail("external evaluator aggregate identity differs")
    if validate_corpus(aggregate["corpus"]) != corpus:
        fail("external evaluator corpus identity differs")
    sandbox = exact_object(
        aggregate["sandbox"],
        {
            "candidate_so_sha256",
            "cpa_version",
            "cpa_commit",
            "cpa_image_id",
            "counted_mock_image_id",
            "sandbox_id",
            "daemon_id",
            "probe_image_id",
            "network_binding",
            "phase_protocol",
            "production_accessed",
            "real_provider_contacted",
            "runtime_checks",
            "decision_audit",
        },
        "aggregate sandbox",
    )
    if (
        sandbox["candidate_so_sha256"] != candidate["so_sha256"]
        or sandbox["sandbox_id"] != execution["sandbox_id"]
        or sandbox["daemon_id"] != execution["daemon_id"]
        or sandbox["probe_image_id"] != execution["probe_image_id"]
        or sandbox["cpa_version"] != "v7.2.95"
        or sandbox["cpa_commit"] != "f71ec0eb6776854457892452cf28c47f0d658251"
        or sandbox["cpa_image_id"] != execution["cpa_image_id"]
        or sandbox["counted_mock_image_id"] != execution["counted_mock_image_id"]
        or sandbox["network_binding"] != execution["network_binding"]
        or sandbox["phase_protocol"] != execution["phase_protocol"]
        or sandbox["production_accessed"] is not False
        or sandbox["real_provider_contacted"] is not False
    ):
        fail("external evaluator sandbox binding differs")
    metrics = validate_metrics(aggregate["metrics"])
    public_counted = validate_public_counted_mock(aggregate["public_counted_mock"])
    if public_counted != metrics["public_counted_mock"]:
        fail("external evaluator public counted-Mock aggregate/metrics binding differs")
    validate_runtime_checks(sandbox["runtime_checks"])
    if sandbox["runtime_checks"] != metrics["runtime_checks"]:
        fail("external evaluator sandbox/runtime metrics binding differs")
    validate_decision_audit(sandbox["decision_audit"])
    if sandbox["decision_audit"] != metrics["decision_audit"]:
        fail("external evaluator sandbox/decision-audit metrics binding differs")
    validate_privacy(aggregate["privacy"])
    return aggregate


def run_external_evaluator(
    config: dict[str, Any],
    args: argparse.Namespace,
    candidate_so: Path,
    candidate: dict[str, Any],
    corpus: dict[str, Any],
    execution: dict[str, Any],
    public_root: Path,
    public_evidence_path: Path,
    public_identity: dict[str, Any],
    work: Path,
) -> dict[str, Any]:
    encrypted = Path(config["corpus"]["encrypted_bundle"])
    decrypted_archive = work / "independent-corpus.tar"
    decrypt = [
        str(config["_age"]),
        "--decrypt",
        "--identity",
        config["corpus"]["age_identity"],
        "--output",
        str(decrypted_archive),
        str(encrypted),
    ]
    completed = subprocess.run(
        decrypt,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=minimal_subprocess_env(home=str(work)),
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        fail("age failed to decrypt the independent corpus")
    os.chmod(decrypted_archive, 0o400)
    corpus_root = work / "corpus"
    safe_extract_corpus(decrypted_archive, corpus_root)
    if sha256_file(corpus_root / "bundle-manifest.signed.json") != corpus["bundle_manifest_sha256"]:
        fail("decrypted corpus signed manifest differs from root-pinned identity")
    os.chmod(decrypted_archive, 0o600)
    decrypted_archive.unlink()

    adapter_work = work / "sandbox"
    adapter_work.mkdir(mode=0o700)
    descriptor = work / "sandbox-descriptor.json"
    adapter_command = [
        str(config["_sandbox_adapter"]),
        "start",
        "--config",
        str(config["_sandbox_adapter_config"]),
        "--candidate-so",
        str(candidate_so),
        "--work",
        str(adapter_work),
        "--challenge",
        args.challenge,
        "--output",
        str(descriptor),
    ]
    aggregate_path = work / "aggregate.json"
    expectations_path = work / "audit-expectations.json"
    finalize_path = work / "sandbox-finalize.json"
    aggregate_value: dict[str, Any] | None = None
    try:
        adapter = subprocess.run(
            adapter_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=minimal_subprocess_env(home=str(adapter_work)),
            check=False,
            timeout=600,
        )
        if adapter.returncode != 0:
            fail("root-owned CPA sandbox adapter failed")

        evaluator_command = [
            str(config["_evaluator"]),
            "--corpus-root",
            str(corpus_root),
            "--signed-manifest",
            str(corpus_root / "bundle-manifest.signed.json"),
            "--author-public-key",
            config["corpus"]["author_public_key"],
            "--author-key-id",
            config["identities"]["author_key_id"],
            "--bundle-sha256",
            corpus["bundle_sha256"],
            "--public-corpus-root",
            str(public_root),
            "--public-development-evidence",
            str(public_evidence_path),
            "--sandbox-descriptor",
            str(descriptor),
            "--expected-candidate-so-sha256",
            candidate["so_sha256"],
            "--expected-core-sha256",
            config["identities"]["core_sha256"],
            "--challenge",
            args.challenge,
            "--output",
            str(aggregate_path),
            "--audit-expectations-output",
            str(expectations_path),
        ]
        evaluator = subprocess.run(
            evaluator_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=minimal_subprocess_env(home=str(work)),
            check=False,
            timeout=7200,
        )
        if evaluator.returncode != 0:
            fail("external evaluator failed")
        finalized = subprocess.run(
            [
                str(config["_sandbox_adapter"]),
                "finalize",
                "--config",
                str(config["_sandbox_adapter_config"]),
                "--work",
                str(adapter_work),
                "--descriptor",
                str(descriptor),
                "--expectations",
                str(expectations_path),
                "--output",
                str(finalize_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=minimal_subprocess_env(home=str(adapter_work)),
            check=False,
            timeout=1200,
        )
        if finalized.returncode != 0:
            fail("root-owned CPA sandbox post-evaluation finalize failed")
        aggregate_value = load_json(aggregate_path, "external evaluator aggregate")
        report = exact_object(
            load_json(finalize_path, "sandbox post-evaluation finalize report"),
            {
                "schema",
                "expectations_sha256",
                "runtime_checks",
                "decision_audit",
                "public_decision_audit",
            },
            "sandbox post-evaluation finalize report",
        )
        require_literal(
            report["schema"], "round9-cpa-sandbox-finalize/v2", "sandbox finalize schema"
        )
        validate_runtime_checks(report["runtime_checks"])
        validate_decision_audit(report["decision_audit"])
        if report["expectations_sha256"] != report["decision_audit"]["expectations_sha256"]:
            fail("sandbox finalize expectations binding differs")
        if not isinstance(aggregate_value, dict):
            fail("external evaluator aggregate must be an object")
        exact_object(
            aggregate_value,
            {
                "schema",
                "evaluator",
                "corpus",
                "sandbox",
                "metrics",
                "public_counted_mock_transport",
                "privacy",
            },
            "provisional external evaluator aggregate",
        )
        metrics = aggregate_value.get("metrics")
        sandbox = aggregate_value.get("sandbox")
        if not isinstance(metrics, dict) or not isinstance(sandbox, dict):
            fail("external evaluator aggregate metrics/sandbox are invalid")
        metrics["runtime_checks"] = report["runtime_checks"]
        metrics["decision_audit"] = report["decision_audit"]
        public_transport = aggregate_value.pop("public_counted_mock_transport")
        validate_public_counted_mock_transport(public_transport)
        public_counted = merge_public_counted_mock(
            public_transport,
            report["public_decision_audit"],
        )
        validate_public_counted_mock(public_counted, expected_manifest=public_identity)
        metrics["public_counted_mock"] = public_counted
        aggregate_value["public_counted_mock"] = public_counted
        sandbox["runtime_checks"] = report["runtime_checks"]
        sandbox["decision_audit"] = report["decision_audit"]
    finally:
        cleanup = subprocess.run(
            [
                str(config["_sandbox_adapter"]),
                "stop",
                "--config",
                str(config["_sandbox_adapter_config"]),
                "--work",
                str(adapter_work),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=minimal_subprocess_env(home=str(adapter_work)),
            check=False,
            timeout=600,
        )
        if cleanup.returncode != 0:
            fail("root-owned CPA sandbox adapter cleanup failed")
    if aggregate_value is None:
        fail("external evaluator aggregate was not finalized")
    return validate_external_aggregate(
        aggregate_value,
        config,
        candidate,
        corpus,
        execution,
    )


def remote_loader(client: GitHubClient, commit: str):
    def load(repository: str, full_ref: str) -> tuple[str, str]:
        entry = load_ledger_entry(client, repository, full_ref, commit)
        return entry["tag_object_sha"], canonical_bytes(entry["envelope"]).decode("utf-8")

    return load


def write_public_outputs(output: Path, envelope: dict[str, Any], proof: dict[str, Any]) -> None:
    output.mkdir(mode=0o755, parents=False, exist_ok=False)
    envelope_path = output / "round9-external-evaluation.json"
    proof_path = output / "round9-external-ledger-proof.json"
    atomic_write(envelope_path, canonical_bytes(envelope), mode=0o644)
    atomic_write(proof_path, canonical_bytes(proof), mode=0o644)


def abort_verified_partial_ledger(
    client: GitHubClient,
    config: dict[str, Any],
    namespace: str,
    base: dict[str, Any],
    commit: str,
    *,
    fail_after_abort: bool = True,
) -> bool:
    repository = config["repository"]
    if client.ref(repository, ledger_ref(namespace, "result"), absent_ok=True) is not None:
        fail("completed external evaluation ledger cannot be aborted")

    def verify_event(event: str) -> bool:
        full_ref = ledger_ref(namespace, event)
        if client.ref(repository, full_ref, absent_ok=True) is None:
            return False
        entry = load_ledger_entry(client, repository, full_ref, commit)
        payload = verify_signed_envelope(
            entry["envelope"],
            Path(config["signing"]["public_key"]),
            config["identities"]["evaluator_key_id"],
            expected_payload_schema=LEDGER_EVENT_SCHEMA,
            openssl=str(config["_openssl"]),
        )
        validate_ledger_event_payload(payload, event)
        expected = ledger_event_payload(event, **base)
        if payload != expected:
            fail("existing partial ledger event differs from this exact evaluation identity")
        return True

    existing: list[str] = []
    for event in ("reserved", "started"):
        if verify_event(event):
            existing.append(event)
    if "started" in existing and "reserved" not in existing:
        fail("partial ledger contains started without reserved")
    aborted_exists = verify_event("aborted")
    if not existing:
        return aborted_exists
    if not aborted_exists:
        create_event(
            client,
            config,
            "aborted",
            ledger_event_payload("aborted", **base),
            commit,
        )
    if fail_after_abort:
        fail("authenticated partial external evaluation was permanently aborted")
    return True


def recover_abort_once(config: dict[str, Any], args: argparse.Namespace) -> str:
    """Authenticate one exact partial ledger identity and close it as aborted."""

    token = read_secret(Path(config["github"]["token_file"]), "root GitHub token")
    client = GitHubClient(config["github"]["api_url"], token)
    verify_remote_identity(client, args, require_failed_host_run=True)
    verify_ledger_ruleset(client, config)
    corpus = corpus_identity(config)
    namespace = ledger_namespace(corpus["bundle_sha256"])
    repository = config["repository"]
    if client.ref(repository, ledger_ref(namespace, "result"), absent_ok=True) is not None:
        fail("completed external evaluation ledger cannot be aborted")
    with tempfile.TemporaryDirectory(
        prefix="cag-round9-recover-abort-", dir=config["_work_root"]
    ) as directory:
        work = Path(directory)
        os.chmod(work, 0o700)
        assets = work / "phase1-assets"
        _candidate_so, asset_identity, development_evidence = verify_phase1_assets(
            client, config, args, assets
        )
        candidate = candidate_identity(args, asset_identity)
        validate_development_evidence(development_evidence, expected_candidate=candidate)
        base = {
            "repository": repository,
            "namespace": namespace,
            "candidate": candidate,
            "evaluator": evaluator_identity(config),
            "corpus": corpus,
            "execution": execution_identity(config, args),
            "development_evidence": development_evidence,
        }
        verify_ledger_ruleset(client, config)
        if not abort_verified_partial_ledger(
            client,
            config,
            namespace,
            base,
            args.commit,
            fail_after_abort=False,
        ):
            fail("no authenticated partial external evaluation exists to abort")
        verify_ledger_ruleset(client, config)
        aborted = load_ledger_entry(
            client,
            repository,
            ledger_ref(namespace, "aborted"),
            args.commit,
        )
        payload = verify_signed_envelope(
            aborted["envelope"],
            Path(config["signing"]["public_key"]),
            config["identities"]["evaluator_key_id"],
            expected_payload_schema=LEDGER_EVENT_SCHEMA,
            openssl=str(config["_openssl"]),
        )
        validate_ledger_event_payload(payload, "aborted")
        if payload != ledger_event_payload("aborted", **base):
            fail("recovered aborted ledger event differs from the exact evaluation identity")
    return namespace


def evaluate_once(config: dict[str, Any], args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    token = read_secret(Path(config["github"]["token_file"]), "root GitHub token")
    client = GitHubClient(config["github"]["api_url"], token)
    verify_remote_identity(client, args)
    verify_ledger_ruleset(client, config)
    corpus = corpus_identity(config)
    namespace = ledger_namespace(corpus["bundle_sha256"])
    state = config["_state_root"] / corpus["bundle_sha256"]
    result_ref = ledger_ref(namespace, "result")
    with tempfile.TemporaryDirectory(prefix="cag-round9-eval-", dir=config["_work_root"]) as directory:
        work = Path(directory)
        os.chmod(work, 0o700)
        assets = work / "phase1-assets"
        candidate_so, asset_identity, development_evidence = verify_phase1_assets(
            client, config, args, assets
        )
        candidate = candidate_identity(args, asset_identity)
        validate_development_evidence(development_evidence, expected_candidate=candidate)
        public_evidence = development_evidence["corpus"]["public_adversarial"]
        public_root = work / "public-development-corpus"
        public_identity = safe_extract_public_development_corpus(
            assets / "cyber-abuse-guard-v0.16-rc.3-source.tar.gz",
            public_root,
            public_evidence,
        )
        public_evidence_path = work / "public-development-evidence.json"
        atomic_write(
            public_evidence_path,
            canonical_bytes(public_evidence),
            mode=0o400,
        )
        evaluator = evaluator_identity(config)
        execution = execution_identity(config, args)
        ledger = {
            "repository": config["repository"],
            "namespace": namespace,
            "reserved_ref": ledger_ref(namespace, "reserved"),
            "started_ref": ledger_ref(namespace, "started"),
            "result_ref": ledger_ref(namespace, "result"),
        }
        base = {
            "repository": config["repository"],
            "namespace": namespace,
            "candidate": candidate,
            "evaluator": evaluator,
            "corpus": corpus,
            "execution": execution,
            "development_evidence": development_evidence,
        }
        if client.ref(config["repository"], result_ref, absent_ok=True) is not None:
            envelope_path = state / "round9-external-evaluation.json"
            proof_path = state / "round9-external-ledger-proof.json"
            envelope = load_canonical_json(envelope_path, "stored external evaluation")
            payload = verify_signed_envelope(
                envelope,
                Path(config["signing"]["public_key"]),
                config["identities"]["evaluator_key_id"],
                expected_payload_schema=EVALUATION_SCHEMA,
                openssl=str(config["_openssl"]),
            )
            validate_evaluation_payload(
                payload, expected_candidate=candidate, challenge=args.challenge
            )
            if (
                payload["evaluator"] != evaluator
                or payload["corpus"] != corpus
                or payload["execution"] != execution
                or payload["ledger"] != ledger
                or payload["development_evidence"] != development_evidence
                or payload["counted_mock"]
                != derive_counted_mock(payload["metrics"], execution)
                or validate_public_counted_mock(
                    payload["public_counted_mock"], expected_manifest=public_identity
                )
                != payload["public_counted_mock"]
            ):
                fail("stored completed evaluation identity differs")
            if proof_path.exists():
                proof = load_canonical_json(proof_path, "stored external ledger proof")
            else:
                proof = build_proof(client, config, namespace, args.commit)
                atomic_write(proof_path, canonical_bytes(proof), mode=0o600)
            validate_ledger_proof(
                proof,
                envelope,
                payload,
                Path(config["signing"]["public_key"]),
                config["identities"]["evaluator_key_id"],
                remote_loader=remote_loader(client, args.commit),
            )
            verify_ledger_ruleset(client, config)
            return envelope, proof

        if client.ref(
            config["repository"], ledger_ref(namespace, "aborted"), absent_ok=True
        ) is not None:
            fail("external evaluation ledger is permanently aborted")
        abort_verified_partial_ledger(
            client, config, namespace, base, args.commit
        )
        reserved_created = False
        try:
            verify_ledger_ruleset(client, config)
            create_event(
                client,
                config,
                "reserved",
                ledger_event_payload("reserved", **base),
                args.commit,
            )
            reserved_created = True
            create_event(
                client,
                config,
                "started",
                ledger_event_payload("started", **base),
                args.commit,
            )
            aggregate = run_external_evaluator(
                config,
                args,
                candidate_so,
                candidate,
                corpus,
                execution,
                public_root,
                public_evidence_path,
                public_identity,
                work,
            )
            counted_mock = derive_counted_mock(aggregate["metrics"], execution)
            validate_counted_mock(counted_mock, aggregate["metrics"], execution)
            public_counted_mock = validate_public_counted_mock(
                aggregate["public_counted_mock"], expected_manifest=public_identity
            )
            payload = validate_evaluation_payload(
                {
                    "schema": EVALUATION_SCHEMA,
                    "state": "PASS",
                    "candidate": candidate,
                    "evaluator": evaluator,
                    "corpus": corpus,
                    "execution": execution,
                    "ledger": ledger,
                    "development_evidence": development_evidence,
                    "counted_mock": counted_mock,
                    "public_counted_mock": public_counted_mock,
                    "metrics": aggregate["metrics"],
                    "privacy": aggregate["privacy"],
                },
                expected_candidate=candidate,
                challenge=args.challenge,
            )
            envelope = signed_envelope(
                payload,
                Path(config["signing"]["private_key"]),
                config["identities"]["evaluator_key_id"],
                openssl=str(config["_openssl"]),
            )
            evaluation_digest = sha256_bytes(canonical_bytes(envelope))
            state.mkdir(mode=0o700)
            atomic_write(
                state / "round9-external-evaluation.json",
                canonical_bytes(envelope),
                mode=0o600,
            )
            verify_ledger_ruleset(client, config)
            create_event(
                client,
                config,
                "result",
                ledger_event_payload(
                    "result",
                    **base,
                    counted_mock=counted_mock,
                    public_counted_mock=public_counted_mock,
                    evaluation_digest=evaluation_digest,
                ),
                args.commit,
            )
            proof = build_proof(client, config, namespace, args.commit)
            validate_ledger_proof(
                proof,
                envelope,
                payload,
                Path(config["signing"]["public_key"]),
                config["identities"]["evaluator_key_id"],
                remote_loader=remote_loader(client, args.commit),
            )
            verify_ledger_ruleset(client, config)
            atomic_write(
                state / "round9-external-ledger-proof.json",
                canonical_bytes(proof),
                mode=0o600,
            )
            return envelope, proof
        except Exception:
            if reserved_created and client.ref(
                config["repository"], result_ref, absent_ok=True
            ) is None and client.ref(
                config["repository"], ledger_ref(namespace, "aborted"), absent_ok=True
            ) is None:
                try:
                    verify_ledger_ruleset(client, config)
                    create_event(
                        client,
                        config,
                        "aborted",
                        ledger_event_payload("aborted", **base),
                        args.commit,
                    )
                except Exception:
                    pass
            raise


def output_path(config: dict[str, Any], value: Path) -> Path:
    if not value.is_absolute() or value.exists() or value.is_symlink():
        fail("broker output must be a new absolute path")
    parent = value.parent.resolve()
    allowed = config["_allowed_output_root"]
    if parent != allowed and allowed not in parent.parents:
        fail("broker output escapes the root-owned allowed output boundary")
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    evaluate = commands.add_parser("evaluate")
    recover = commands.add_parser("recover-abort")
    for command in (evaluate, recover):
        command.add_argument("--repository", required=True)
        command.add_argument("--tag", required=True)
        command.add_argument("--tag-object-sha", required=True)
        command.add_argument("--commit", required=True)
        command.add_argument("--tree", required=True)
        command.add_argument("--phase1-run-id", required=True, type=int)
        command.add_argument("--phase1-run-attempt", required=True, type=int)
        command.add_argument("--phase1-artifact-id", required=True, type=int)
        command.add_argument("--phase1-artifact-digest", required=True)
        command.add_argument("--candidate-identity", required=True)
        command.add_argument("--challenge", required=True)
        command.add_argument("--workflow-run-id", required=True, type=int)
        command.add_argument("--workflow-run-attempt", required=True, type=int)
        command.add_argument("--dispatch-ref", required=True)
        command.add_argument("--dispatch-sha", required=True)
        command.add_argument("--workflow-ref", required=True)
        command.add_argument("--workflow-sha", required=True)
    evaluate.add_argument("--output", required=True, type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            fail("the external evaluation broker must run as root")
        apply_candidate_identity_input(args)
        config = load_config()
        validate_dispatch(args, config["repository"])
        if args.command == "recover-abort":
            namespace = recover_abort_once(config, args)
        else:
            output = output_path(config, args.output)
            envelope, proof = evaluate_once(config, args)
            write_public_outputs(output, envelope, proof)
    except (ContractError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"cag-round9-eval-broker: FAIL: {exc}", file=sys.stderr)
        return 1
    if args.command == "recover-abort":
        print(f"cag-round9-eval-broker: ABORTED namespace={namespace}")
    else:
        print(
            "cag-round9-eval-broker: PASS "
            f"evaluation_sha256={sha256_bytes(canonical_bytes(envelope))} "
            f"ledger_proof_sha256={sha256_bytes(canonical_bytes(proof))}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
