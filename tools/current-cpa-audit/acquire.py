#!/usr/bin/env python3
"""Acquire a five-repository corpus or one reviewed local supplemental ZIP.

Only allowlisted text blobs and one single-entry Markdown ZIP are read.  No
third-party repository code, installer, hook, macro, binary, or dependency is
ever invoked.  The supplemental action writes metadata only; selected member
text is validated in memory and the operator-owned archive is never removed.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from audit_contract import (
    ALLOWED_GITHUB_HOSTS,
    AUTHORIZATION_VALUES,
    CLAIM_BOUNDARY,
    CORPUS_SCHEMA,
    CURRENT_ACTION_VALUES,
    EXPECTED_SEMANTIC_CASE_COUNT,
    FIXED_REPOSITORIES,
    FIXED_SOURCE_PATHS,
    FIXED_SOURCE_RETENTION,
    HEX40,
    LABELS,
    OWNERSHIP_VALUES,
    POLICY_SCHEMA,
    POLICY_REVIEW_STATUSES,
    REPOSITORY,
    REVIEWED_SOURCE_FIELDS,
    SOURCE_RETENTION_VALUES,
    TEMPLATE_BYTES,
    TEMPLATE_SHA256,
    BoundCorpus,
    ContractError,
    canonical_bytes,
    exact_int,
    exact_keys,
    exact_list,
    fail,
    load_json_bytes,
    nonempty_string,
    one_of,
    read_regular_bytes,
    require_hex,
    require_safe_relative,
    require_timestamp,
    review_sha256,
    sha256_bytes,
    unlink_corpus_file,
    validate_corpus_manifest,
    validate_expected_actions,
    validate_inert_text,
    validate_manifest_policy,
    validate_semantic_case,
    validate_supplemental_manifest,
    validate_supplemental_policy,
)
from supplemental_zip import create_supplemental_manifest


MAX_API_BYTES = 32 * 1024 * 1024
MAX_POLICY_BYTES = 2 * 1024 * 1024
USER_AGENT = "cag-current-cpa-audit-acquirer/1"
GIT_LFS_PREFIX = b"version https://git-lfs.github.com/spec/v1"
SUPPLEMENTAL_MANIFEST_NAME = "supplemental-zip-manifest.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class FetchReceipt:
    observed_at: str
    url: str
    body_sha256: str
    etag: str

    def api_dict(self) -> dict[str, Any]:
        return {
            "api_body_sha256": self.body_sha256,
            "api_url": self.url,
            "etag": self.etag,
            "observed_at": self.observed_at,
        }


class RestrictedRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        validate_github_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_github_url(url: str) -> None:
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname not in ALLOWED_GITHUB_HOSTS
        or parts.port not in (None, 443)
        or parts.username
        or parts.password
        or parts.fragment
        or not parts.path.startswith("/")
        or "\\" in parts.path
    ):
        fail("URL escaped the fixed HTTPS GitHub host contract")


class GitHubClient:
    def __init__(self) -> None:
        self._opener = build_opener(ProxyHandler({}), RestrictedRedirect())

    def fetch(self, url: str, maximum: int) -> tuple[bytes, FetchReceipt]:
        validate_github_url(url)
        last_error = "unavailable"
        for attempt in range(3):
            request = Request(
                url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": USER_AGENT,
                },
            )
            try:
                with self._opener.open(request, timeout=30) as response:
                    final_url = response.geturl()
                    validate_github_url(final_url)
                    declared = response.headers.get("Content-Length")
                    if declared is not None:
                        try:
                            declared_bytes = int(declared)
                        except ValueError:
                            fail("GitHub response Content-Length is invalid")
                        if declared_bytes < 0 or declared_bytes > maximum:
                            fail("GitHub response exceeds the byte limit before read")
                    raw = response.read(maximum + 1)
                    if len(raw) > maximum:
                        fail("GitHub response exceeds the byte limit")
                    etag = response.headers.get("ETag", "").strip()
                    if not etag:
                        fail("GitHub response lacks ETag")
                    receipt = FetchReceipt(now_iso(), final_url, sha256_bytes(raw), etag)
                    return raw, receipt
            except ContractError:
                raise
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                last_error = type(exc).__name__
                if attempt < 2:
                    time.sleep(0.25 * (attempt + 1))
        fail(f"GitHub fetch failed after bounded retries: {last_error}")

    def json(self, url: str, maximum: int = MAX_API_BYTES) -> tuple[Any, FetchReceipt]:
        raw, receipt = self.fetch(url, maximum)
        return load_json_bytes(raw, f"GitHub API body {url}", maximum), receipt


def git_blob_sha1(raw: bytes) -> str:
    prefix = b"blob " + str(len(raw)).encode("ascii") + b"\x00"
    # Git blob identity is defined with SHA-1; this is not a security digest.
    return hashlib.sha1(prefix + raw, usedforsecurity=False).hexdigest()


def safe_file_name(repository_key: str, source_path: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", source_path).strip("-.")[:100]
    digest = sha256_bytes(source_path.encode("utf-8"))[:16]
    return f"{repository_key}--{stem or 'source'}--{digest}.txt"


def write_exclusive(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except FileExistsError:
        fail(f"refusing to replace an existing acquisition output: {path}")
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
            if os.fstat(output.fileno()).st_nlink != 1:
                fail(f"new acquisition output acquired an external hard link: {path}")
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    post = path.lstat()
    if not stat.S_ISREG(post.st_mode) or post.st_nlink != 1:
        if stat.S_ISREG(post.st_mode) or stat.S_ISLNK(post.st_mode):
            path.unlink(missing_ok=True)
        fail(f"new acquisition output identity changed or acquired a hard link: {path}")
    os.chmod(path, mode)


def _mkdir_private_parents(path: Path) -> None:
    """Create a private directory tree without exposing intermediate parents."""

    previous_umask = os.umask(0o077)
    try:
        path.mkdir(parents=True, mode=0o700)
    finally:
        os.umask(previous_umask)
    os.chmod(path, 0o700)


def remove_private_tree(root: Path) -> int:
    """Remove only a newly-created acquisition tree without following links."""

    try:
        info = root.lstat()
    except FileNotFoundError:
        return 0
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("refusing cleanup because the acquisition root identity changed")
    removed = 0
    with os.scandir(root) as entries:
        children = [Path(entry.path) for entry in entries]
    for child in children:
        child_info = child.lstat()
        if stat.S_ISDIR(child_info.st_mode) and not stat.S_ISLNK(child_info.st_mode):
            removed += remove_private_tree(child)
        else:
            child.unlink()
            removed += 1
    root.rmdir()
    return removed


def _zip_exact_layout(raw: bytes) -> tuple[int, int] | None:
    # EOCD is at least 22 bytes; its two-byte comment length binds the end.
    # The central-directory offset stored in EOCD is relative to the start of
    # the ZIP. Requiring it to end exactly at EOCD rejects self-extracting
    # prefixes and concatenated archives that zipfile would otherwise accept
    # by silently rebasing the final archive.
    signature = b"PK\x05\x06"
    offset = raw.rfind(signature, max(0, len(raw) - (65535 + 22)))
    if offset < 0 or offset + 22 > len(raw):
        return None
    comment_length = int.from_bytes(raw[offset + 20 : offset + 22], "little")
    if offset + 22 + comment_length != len(raw):
        return None
    disk_number = int.from_bytes(raw[offset + 4 : offset + 6], "little")
    directory_disk = int.from_bytes(raw[offset + 6 : offset + 8], "little")
    entries_on_disk = int.from_bytes(raw[offset + 8 : offset + 10], "little")
    total_entries = int.from_bytes(raw[offset + 10 : offset + 12], "little")
    directory_size = int.from_bytes(raw[offset + 12 : offset + 16], "little")
    directory_offset = int.from_bytes(raw[offset + 16 : offset + 20], "little")
    if (
        disk_number != 0
        or directory_disk != 0
        or entries_on_disk != 1
        or total_entries != 1
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
        or directory_offset + directory_size != offset
        or raw[directory_offset : directory_offset + 4] != b"PK\x01\x02"
    ):
        return None
    return directory_offset, directory_size


def extract_single_markdown_zip(raw: bytes, expected_member: str, maximum: int) -> bytes:
    require_safe_relative(expected_member, "Markdown ZIP member")
    if "/" in expected_member or not expected_member.lower().endswith(".md"):
        fail("Markdown ZIP member must be one root-level .md file")
    layout = _zip_exact_layout(raw)
    if not raw.startswith(b"PK\x03\x04") or layout is None:
        fail("Markdown ZIP has a prefix, trailer, or invalid EOCD")
    directory_offset, _ = layout
    try:
        with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
            infos = archive.infolist()
            if len(infos) != 1:
                fail("Markdown ZIP must contain exactly one entry")
            info = infos[0]
            if archive.start_dir != directory_offset or info.header_offset != 0:
                fail("Markdown ZIP has a prefix or rebased archive")
            unix_mode = (info.external_attr >> 16) & 0o177777
            file_type = stat.S_IFMT(unix_mode)
            if (
                info.filename != expected_member
                or info.orig_filename != expected_member
                or info.is_dir()
                or info.flag_bits & 1
                or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                or file_type == stat.S_IFLNK
                or file_type not in (0, stat.S_IFREG)
                or info.file_size <= 0
                or info.file_size > maximum
                or info.compress_size <= 0
                or info.file_size > info.compress_size * 100
            ):
                fail("Markdown ZIP entry violates the closed archive contract")
            local_name_length = int.from_bytes(raw[26:28], "little")
            local_extra_length = int.from_bytes(raw[28:30], "little")
            local_data_start = 30 + local_name_length + local_extra_length
            if (
                info.flag_bits & 0x08
                or raw[30 : 30 + local_name_length] != expected_member.encode("utf-8")
                or local_data_start + info.compress_size != directory_offset
            ):
                fail("Markdown ZIP local entry is not the sole archive payload")
            extracted = archive.read(info)
    except ContractError:
        raise
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError) as exc:
        fail(f"Markdown ZIP is invalid: {type(exc).__name__}")
    if len(extracted) > maximum:
        fail("Markdown ZIP expanded beyond the byte limit")
    return validate_inert_text(extracted, "Markdown ZIP text", maximum)


def require_reviewed_digest(
    value: Any, label: str, pattern: re.Pattern[str] | None = None
) -> str:
    digest = require_hex(value, label) if pattern is None else require_hex(value, label, pattern)
    if not digest.strip("0"):
        fail(f"{label} must not be an all-zero placeholder")
    return digest


def validate_policy(value: Any, *, require_approved: bool = False) -> dict[str, Any]:
    policy = exact_keys(
        value,
        {"allowed_hosts", "max_blob_bytes", "repositories", "reviewer", "schema"},
        "source policy",
    )
    if policy["schema"] != POLICY_SCHEMA:
        fail("source policy schema is invalid")
    if policy["allowed_hosts"] != list(ALLOWED_GITHUB_HOSTS):
        fail("source policy GitHub hosts are not the fixed allowlist")
    maximum = exact_int(policy["max_blob_bytes"], "source policy.max_blob_bytes", 1)
    if maximum > 2 * 1024 * 1024:
        fail("source policy max blob bytes exceeds 2 MiB")
    reviewer = exact_keys(
        policy["reviewer"],
        {"identity", "reviewed_at", "status"},
        "source policy.reviewer",
    )
    review_status = one_of(
        reviewer["status"], POLICY_REVIEW_STATUSES, "source policy.reviewer.status"
    )
    if require_approved and review_status != "approved":
        fail("source policy is pending human review")
    if review_status == "pending":
        if reviewer["identity"] is not None or reviewer["reviewed_at"] is not None:
            fail("pending source policy must not claim reviewer identity or review time")
    else:
        nonempty_string(reviewer["identity"], "source policy.reviewer.identity", 256)
        require_timestamp(reviewer["reviewed_at"], "source policy.reviewer.reviewed_at")
    repositories = exact_list(policy["repositories"], "source policy.repositories", 5)
    if len(repositories) != 5:
        fail("source policy must contain exactly five repositories")
    repo_keys: set[str] = set()
    repo_slugs: set[str] = set()
    semantic_ids: set[str] = set()
    zip_count = 0
    zip_sources: set[tuple[str, str]] = set()
    for repo_index, raw_repo in enumerate(repositories):
        label = f"source policy.repositories[{repo_index}]"
        repo = exact_keys(raw_repo, {"key", "paths", "repository", "retention"}, label)
        key = nonempty_string(repo["key"], f"{label}.key", 64)
        slug = nonempty_string(repo["repository"], f"{label}.repository", 256)
        if SAFE_REPO_KEY.fullmatch(key) is None or REPOSITORY.fullmatch(slug) is None:
            fail(f"{label} repository identity is invalid")
        if key in repo_keys or slug in repo_slugs:
            fail(f"{label} repository identity is duplicated")
        if FIXED_REPOSITORIES.get(key) != slug:
            fail(f"{label} is not one of the fixed repositories")
        retention = one_of(repo["retention"], SOURCE_RETENTION_VALUES, f"{label}.retention")
        if retention != FIXED_SOURCE_RETENTION[key]:
            fail(f"{label}.retention violates the fixed licence boundary")
        repo_keys.add(key)
        repo_slugs.add(slug)
        paths = exact_list(repo["paths"], f"{label}.paths", 1)
        seen_paths: set[str] = set()
        reviewed_head: tuple[str, str] | None = None
        for path_index, raw_path in enumerate(paths):
            path_label = f"{label}.paths[{path_index}]"
            item = exact_keys(
                raw_path,
                {
                    "archive_member",
                    "kind",
                    "path",
                    "reviewed_source",
                    "semantic_cases",
                },
                path_label,
            )
            path = require_safe_relative(item["path"], f"{path_label}.path")
            if path in seen_paths:
                fail(f"{path_label}.path is duplicated")
            seen_paths.add(path)
            kind = one_of(item["kind"], ("markdown_zip", "text"), f"{path_label}.kind")
            if kind == "markdown_zip":
                zip_count += 1
                zip_sources.add((key, path))
                member = nonempty_string(item["archive_member"], f"{path_label}.archive_member", 256)
                require_safe_relative(member, f"{path_label}.archive_member")
                if "/" in member or not member.lower().endswith(".md"):
                    fail(f"{path_label}.archive_member must be one root Markdown file")
            elif item["archive_member"] is not None:
                fail(f"{path_label}.archive_member must be null for text")
            reviewed_source = exact_keys(
                item["reviewed_source"], REVIEWED_SOURCE_FIELDS, f"{path_label}.reviewed_source"
            )
            if review_status == "pending":
                if any(reviewed_source[field] is not None for field in REVIEWED_SOURCE_FIELDS):
                    fail(f"{path_label}.reviewed_source must be entirely null while pending")
            else:
                commit = require_reviewed_digest(
                    reviewed_source["commit"], f"{path_label}.reviewed_source.commit", HEX40
                )
                tree = require_reviewed_digest(
                    reviewed_source["tree"], f"{path_label}.reviewed_source.tree", HEX40
                )
                require_reviewed_digest(
                    reviewed_source["blob_sha1"],
                    f"{path_label}.reviewed_source.blob_sha1",
                    HEX40,
                )
                require_reviewed_digest(
                    reviewed_source["source_sha256"],
                    f"{path_label}.reviewed_source.source_sha256",
                )
                require_reviewed_digest(
                    reviewed_source["text_sha256"],
                    f"{path_label}.reviewed_source.text_sha256",
                )
                if reviewed_head is None:
                    reviewed_head = (commit, tree)
                elif reviewed_head != (commit, tree):
                    fail(f"{label} reviewed sources do not share one exact commit/tree")
            cases = exact_list(item["semantic_cases"], f"{path_label}.semantic_cases", 1)
            for case_index, raw_case in enumerate(cases):
                case_label = f"{path_label}.semantic_cases[{case_index}]"
                case = exact_keys(
                    raw_case,
                    {
                        "authorization",
                        "current_action",
                        "expected_action_by_mode",
                        "id_suffix",
                        "label",
                        "label_reason",
                        "ownership",
                        "template_id",
                    },
                    case_label,
                )
                suffix = nonempty_string(case["id_suffix"], f"{case_label}.id_suffix", 64)
                if SAFE_SUFFIX.fullmatch(suffix) is None:
                    fail(f"{case_label}.id_suffix is unsafe")
                semantic_id = f"{key}:{path}:{suffix}"
                if semantic_id in semantic_ids:
                    fail(f"duplicate semantic case identity: {semantic_id}")
                semantic_ids.add(semantic_id)
                one_of(case["template_id"], tuple(TEMPLATE_BYTES), f"{case_label}.template_id")
                one_of(case["label"], LABELS, f"{case_label}.label")
                nonempty_string(case["label_reason"], f"{case_label}.label_reason", 2048)
                one_of(case["authorization"], AUTHORIZATION_VALUES, f"{case_label}.authorization")
                one_of(case["ownership"], OWNERSHIP_VALUES, f"{case_label}.ownership")
                one_of(case["current_action"], CURRENT_ACTION_VALUES, f"{case_label}.current_action")
                validate_expected_actions(case["expected_action_by_mode"], f"{case_label}.expected_action_by_mode")
        if seen_paths != set(FIXED_SOURCE_PATHS[key]):
            fail(f"{label}.paths does not match the fixed reviewed path set")
    if zip_count != 1:
        fail("source policy must allowlist exactly one Markdown ZIP")
    if zip_sources != {("mdx", "gpt-5.6-sol-unrestricted-v45.zip")}:
        fail("source policy Markdown ZIP identity is not the fixed MDX archive")
    if repo_keys != set(FIXED_REPOSITORIES) or repo_slugs != set(FIXED_REPOSITORIES.values()):
        fail("source policy does not contain the exact fixed repositories")
    if len(semantic_ids) != EXPECTED_SEMANTIC_CASE_COUNT:
        fail("source policy must contain exactly 19 reviewed semantic cases")
    return policy


SAFE_REPO_KEY = re.compile(r"[a-z][a-z0-9_-]{1,31}")
SAFE_SUFFIX = re.compile(r"[a-z][a-z0-9_-]{1,63}")


def _head_identity(commit: Any, label: str) -> tuple[str, str]:
    if not isinstance(commit, dict):
        fail(f"{label} is not an object")
    commit_sha = commit.get("sha")
    tree_sha = (((commit.get("commit") or {}).get("tree") or {}).get("sha"))
    if not isinstance(commit_sha, str) or HEX40.fullmatch(commit_sha) is None:
        fail(f"{label} commit SHA is invalid")
    if not isinstance(tree_sha, str) or HEX40.fullmatch(tree_sha) is None:
        fail(f"{label} tree SHA is invalid")
    return commit_sha, tree_sha


def _head_receipt(receipt: FetchReceipt, commit: str, tree: str) -> dict[str, Any]:
    result = receipt.api_dict()
    result["commit"] = commit
    result["tree"] = tree
    return result


def _tree_entry(value: Any, expected_path: str, maximum: int) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("path") != expected_path:
        fail(f"Git tree entry is invalid for {expected_path}")
    if value.get("type") != "blob" or value.get("mode") != "100644":
        fail(f"non-regular or executable Git tree entry rejected: {expected_path}")
    blob = value.get("sha")
    size = value.get("size")
    if not isinstance(blob, str) or HEX40.fullmatch(blob) is None:
        fail(f"Git blob SHA is invalid for {expected_path}")
    if type(size) is not int or size <= 0 or size > maximum:
        fail(f"Git blob size is invalid for {expected_path}")
    return value


class Acquirer:
    def __init__(self, policy: Mapping[str, Any], client: GitHubClient, output: Path, policy_sha256: str) -> None:
        self.policy = policy
        self.client = client
        self.output = output
        self.policy_sha256 = policy_sha256
        self.maximum = int(policy["max_blob_bytes"])
        self.semantic_cases: list[dict[str, Any]] = []
        self.observations: list[dict[str, Any]] = []
        self.source_identities: set[tuple[str, str, str]] = set()
        self.bound_corpus: BoundCorpus | None = None
        self.created_corpus: dict[str, tuple[int, str]] = {}
        self.filesystem_identity: dict[str, dict[str, int]] = {}

    def acquire(self) -> dict[str, Any]:
        if self.output.exists() or self.output.is_symlink():
            fail("acquisition output must be a new path")
        self.output.mkdir(parents=True, mode=0o700)
        os.chmod(self.output, 0o700)
        try:
            (self.output / "corpus").mkdir(mode=0o700)
            root_info = self.output.lstat()
            corpus_info = (self.output / "corpus").lstat()
            self.filesystem_identity = {
                "acquisition_root": {
                    "device": root_info.st_dev,
                    "inode": root_info.st_ino,
                },
                "corpus_directory": {
                    "device": corpus_info.st_dev,
                    "inode": corpus_info.st_ino,
                },
            }
            self.bound_corpus = BoundCorpus(
                self.output,
                self.filesystem_identity,
                "acquisition corpus",
            )
            for repository in self.policy["repositories"]:
                self._repository(repository)
            root_info = self.output.lstat()
            corpus_info = (self.output / "corpus").lstat()
            if (
                stat.S_ISLNK(root_info.st_mode)
                or not stat.S_ISDIR(root_info.st_mode)
                or stat.S_ISLNK(corpus_info.st_mode)
                or not stat.S_ISDIR(corpus_info.st_mode)
            ):
                fail("acquisition directory identity changed")
            manifest = {
                "acquired_at": now_iso(),
                "artifact_status": "candidate",
                "claim_boundary": CLAIM_BOUNDARY,
                "filesystem_identity": self.filesystem_identity,
                "head_observations": self.observations,
                "policy_sha256": self.policy_sha256,
                "policy_review_status": self.policy["reviewer"]["status"],
                "repository_count": len(self.observations),
                "schema": CORPUS_SCHEMA,
                "semantic_cases": self.semantic_cases,
                "source_count": len(self.source_identities),
                "third_party_code_executions": 0,
                "unique_content_hashes": len(
                    {case["source"]["text_sha256"] for case in self.semantic_cases}
                ),
                "unique_semantic_cases": len(self.semantic_cases),
            }
            validate_corpus_manifest(manifest, self.output)
            validate_manifest_policy(manifest, self.policy)
            write_exclusive(self.output / "corpus-manifest.json", canonical_bytes(manifest) + b"\n")
            validate_corpus_manifest(manifest, self.output)
            self.bound_corpus.close()
            self.bound_corpus = None
            return manifest
        except BaseException:
            # Especially for the unlicensed NERV source, no complete text may
            # survive an interrupted or rejected acquisition.
            cleanup_problems: list[str] = []
            if self.bound_corpus is not None:
                try:
                    cleanup_problems.extend(self.bound_corpus.identity_problems())
                    for relative, (expected_bytes, expected_sha256) in sorted(
                        self.created_corpus.items()
                    ):
                        _, file_problems = self.bound_corpus.unlink_source(
                            relative, expected_bytes, expected_sha256
                        )
                        cleanup_problems.extend(file_problems)
                    cleanup_problems.extend(self.bound_corpus.finish_cleanup())
                except BaseException as cleanup_exc:
                    cleanup_problems.append(
                        f"bound_cleanup:{type(cleanup_exc).__name__}"
                    )
                finally:
                    self.bound_corpus.close()
                    self.bound_corpus = None
            try:
                remove_private_tree(self.output)
            except BaseException as cleanup_exc:
                cleanup_problems.append(f"path_cleanup:{type(cleanup_exc).__name__}")
            if cleanup_problems:
                fail(
                    "acquisition cleanup failed closed: "
                    + ",".join(sorted(set(cleanup_problems)))
                )
            raise

    def _repository(self, repository: Mapping[str, Any]) -> None:
        key = repository["key"]
        slug = repository["repository"]
        encoded_slug = "/".join(quote(part, safe="") for part in slug.split("/"))
        metadata_url = f"https://api.github.com/repos/{encoded_slug}"
        metadata, metadata_receipt = self.client.json(metadata_url)
        if not isinstance(metadata, dict) or metadata.get("full_name") != slug:
            fail(f"GitHub repository metadata identity mismatch: {slug}")
        default_branch = metadata.get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            fail(f"GitHub repository has no default branch: {slug}")

        head_url = f"https://api.github.com/repos/{encoded_slug}/commits/{quote(default_branch, safe='')}"
        pre_body, pre_receipt = self.client.json(head_url)
        commit, tree = _head_identity(pre_body, f"{slug} pre-head")
        tree_url = f"https://api.github.com/repos/{encoded_slug}/git/trees/{tree}?recursive=1"
        tree_body, tree_receipt = self.client.json(tree_url)
        if not isinstance(tree_body, dict) or tree_body.get("sha") != tree or tree_body.get("truncated") is not False:
            fail(f"GitHub recursive tree is missing or truncated: {slug}")
        entries = tree_body.get("tree")
        if not isinstance(entries, list):
            fail(f"GitHub recursive tree has invalid shape: {slug}")
        by_path: dict[str, Any] = {}
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                fail(f"GitHub recursive tree contains an invalid entry: {slug}")
            path = entry["path"]
            if path in by_path:
                fail(f"GitHub recursive tree contains a duplicate path: {slug}:{path}")
            by_path[path] = entry

        for selected in repository["paths"]:
            self._source(
                key,
                slug,
                encoded_slug,
                commit,
                tree,
                repository["retention"],
                selected,
                by_path,
            )

        post_body, post_receipt = self.client.json(head_url)
        post_commit, post_tree = _head_identity(post_body, f"{slug} post-head")
        if (post_commit, post_tree) != (commit, tree):
            fail(f"repository head moved during acquisition: {slug}")
        observation = {
            "default_branch": default_branch,
            "metadata": metadata_receipt.api_dict(),
            "post": _head_receipt(post_receipt, post_commit, post_tree),
            "pre": _head_receipt(pre_receipt, commit, tree),
            "repository": slug,
            "repository_key": key,
            "tree_api": tree_receipt.api_dict(),
        }
        self.observations.append(observation)

    def _source(
        self,
        key: str,
        slug: str,
        encoded_slug: str,
        commit: str,
        tree: str,
        retention: str,
        selected: Mapping[str, Any],
        by_path: Mapping[str, Any],
    ) -> None:
        path = selected["path"]
        entry = _tree_entry(by_path.get(path), path, self.maximum)
        raw_url = f"https://raw.githubusercontent.com/{encoded_slug}/{commit}/{quote(path, safe='/')}"
        raw, receipt = self.client.fetch(raw_url, self.maximum)
        if len(raw) != entry["size"] or git_blob_sha1(raw) != entry["sha"]:
            fail(f"download does not match the exact Git blob: {slug}:{path}")
        if raw.startswith(GIT_LFS_PREFIX):
            fail(f"Git LFS pointer rejected: {slug}:{path}")
        if selected["kind"] == "markdown_zip":
            text = extract_single_markdown_zip(raw, selected["archive_member"], self.maximum)
            archive_member: str | None = selected["archive_member"]
        else:
            text = validate_inert_text(raw, f"{slug}:{path}", self.maximum)
            archive_member = None

        corpus_file = f"corpus/{safe_file_name(key, path)}"
        if self.bound_corpus is None:
            fail("acquisition corpus binding is unavailable")
        self.created_corpus[corpus_file] = (len(text), sha256_bytes(text))
        self.bound_corpus.write(corpus_file, text)
        source = {
            "archive_member": archive_member,
            "blob_sha1": entry["sha"],
            "commit": commit,
            "corpus_file": corpus_file,
            "path": path,
            "raw_etag": receipt.etag,
            "repository": slug,
            "repository_key": key,
            "retention": retention,
            "source_sha256": sha256_bytes(raw),
            "text_bytes": len(text),
            "text_sha256": sha256_bytes(text),
            "tree": tree,
        }
        self.source_identities.add((key, path, source["text_sha256"]))
        reviewer_policy = self.policy["reviewer"]
        for semantic in selected["semantic_cases"]:
            case = {
                "authorization": semantic["authorization"],
                "current_action": semantic["current_action"],
                "expected_action_by_mode": semantic["expected_action_by_mode"],
                "id": f"{key}:{path}:{semantic['id_suffix']}",
                "label": semantic["label"],
                "label_reason": semantic["label_reason"],
                "ownership": semantic["ownership"],
                "reviewer": {
                    "identity": reviewer_policy["identity"],
                    "review_sha256": None,
                    "reviewed_at": reviewer_policy["reviewed_at"],
                    "status": reviewer_policy["status"],
                },
                "source": dict(source),
                "template": {
                    "id": semantic["template_id"],
                    "sha256": TEMPLATE_SHA256[semantic["template_id"]],
                },
            }
            if reviewer_policy["status"] == "approved":
                case["reviewer"]["review_sha256"] = review_sha256(case)
            validate_semantic_case(case, f"semantic case {case['id']}")
            self.semantic_cases.append(case)


def discard_candidate_texts(manifest_path: Path) -> int:
    """Delete only corpus files named by one canonical candidate manifest."""

    if manifest_path.name != "corpus-manifest.json":
        fail("candidate discard requires a corpus-manifest.json path")
    manifest_raw = read_regular_bytes(
        manifest_path, "candidate manifest", 64 * 1024 * 1024
    )
    manifest = validate_corpus_manifest(
        load_json_bytes(manifest_raw, "candidate manifest", 64 * 1024 * 1024)
    )
    if manifest_raw != canonical_bytes(manifest) + b"\n":
        fail("candidate manifest is not canonical JSON with one terminal newline")
    root = manifest_path.parent
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        fail("candidate acquisition root is missing")
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        fail("candidate acquisition root must be a real directory")
    if os.name == "posix" and root_info.st_mode & 0o077:
        fail("candidate acquisition root must be mode-0700 or stricter")
    bound = BoundCorpus(root, manifest["filesystem_identity"], "candidate corpus discard")
    try:
        bound.verify_manifest_files(manifest)
        problems = bound.identity_problems()
        sources: dict[str, Mapping[str, Any]] = {}
        for case in manifest["semantic_cases"]:
            source = case["source"]
            sources.setdefault(source["corpus_file"], source)
        removed = 0
        for relative, source in sorted(sources.items()):
            was_removed, file_problems = bound.unlink_source(
                relative,
                source["text_bytes"],
                source["text_sha256"],
            )
            removed += int(was_removed)
            problems.extend(file_problems)
        problems.extend(bound.finish_cleanup())
        if problems:
            fail("candidate corpus discard incomplete: " + ",".join(sorted(set(problems))))
        return removed
    finally:
        bound.close()


def load_supplemental_policy(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = read_regular_bytes(
        path,
        "supplemental ZIP policy",
        MAX_POLICY_BYTES,
        require_single_link=True,
    )
    policy = validate_supplemental_policy(
        load_json_bytes(raw, "supplemental ZIP policy", MAX_POLICY_BYTES),
    )
    return policy, raw


def acquire_supplemental_zip(
    archive_path: Path, policy_path: Path, output: Path
) -> dict[str, Any]:
    """Write one metadata-only candidate; member text never leaves memory."""

    if output.exists() or output.is_symlink():
        fail("supplemental acquisition output must be a new path")
    _mkdir_private_parents(output)
    try:
        policy, policy_raw = load_supplemental_policy(policy_path)
        manifest = create_supplemental_manifest(
            archive_path,
            policy,
            sha256_bytes(policy_raw),
            now_iso(),
        )
        raw = canonical_bytes(manifest) + b"\n"
        write_exclusive(output / SUPPLEMENTAL_MANIFEST_NAME, raw)
        validate_supplemental_manifest(
            manifest,
            policy,
            policy_sha256=sha256_bytes(policy_raw),
        )
        return manifest
    except BaseException as primary_error:
        try:
            remove_private_tree(output)
        except BaseException as cleanup_exc:
            primary_error.add_note(
                "supplemental acquisition cleanup also failed; "
                "acquisition remains failed closed: "
                f"{type(cleanup_exc).__name__}"
            )
        raise


def validate_supplemental_candidate(
    manifest_path: Path, policy_path: Path
) -> dict[str, Any]:
    if manifest_path.name != SUPPLEMENTAL_MANIFEST_NAME:
        fail(f"supplemental candidate must be named {SUPPLEMENTAL_MANIFEST_NAME}")
    raw = read_regular_bytes(
        manifest_path,
        "supplemental ZIP manifest",
        16 * 1024 * 1024,
        require_single_link=True,
    )
    value = load_json_bytes(raw, "supplemental ZIP manifest", 16 * 1024 * 1024)
    if raw != canonical_bytes(value) + b"\n":
        fail("supplemental ZIP manifest must be canonical JSON with one terminal newline")
    policy, policy_raw = load_supplemental_policy(policy_path)
    manifest = validate_supplemental_manifest(
        value,
        policy,
        policy_sha256=sha256_bytes(policy_raw),
    )
    root = manifest_path.parent
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        fail("supplemental acquisition root is missing")
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        fail("supplemental acquisition root must be a real directory")
    if os.name == "posix" and root_info.st_mode & 0o077:
        fail("supplemental acquisition root must be mode-0700 or stricter")
    children = list(root.iterdir())
    if children != [manifest_path]:
        fail("supplemental acquisition root contains unexpected files")
    return manifest


def discard_supplemental_candidate(manifest_path: Path, policy_path: Path) -> int:
    """Remove only task-created metadata, never the operator-owned archive."""

    validate_supplemental_candidate(manifest_path, policy_path)
    removed, problems = unlink_corpus_file(
        manifest_path, "supplemental-zip-manifest.json"
    )
    if not removed or problems:
        fail(
            "supplemental candidate discard failed closed: "
            + ",".join(problems or ["manifest_not_removed"])
        )
    try:
        manifest_path.parent.rmdir()
    except OSError as exc:
        fail(f"supplemental candidate root removal failed: {type(exc).__name__}")
    return 1


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--policy", type=Path, help="fixed candidate-selection/review policy JSON"
    )
    action.add_argument(
        "--discard-candidate",
        type=Path,
        metavar="MANIFEST",
        help="remove only private corpus text named by a canonical candidate manifest",
    )
    action.add_argument(
        "--supplemental-archive",
        dest="supplemental_zip",
        type=Path,
        metavar="ARCHIVE",
        help="read one reviewed local ZIP and write metadata only",
    )
    action.add_argument(
        "--validate-supplemental",
        type=Path,
        metavar="MANIFEST",
        help="validate one canonical metadata-only supplemental candidate",
    )
    action.add_argument(
        "--discard-supplemental",
        type=Path,
        metavar="MANIFEST",
        help="remove only a validated task-created supplemental manifest/root",
    )
    parser.add_argument(
        "--supplemental-policy",
        type=Path,
        help="reviewed supplemental ZIP policy JSON",
    )
    parser.add_argument("--output", type=Path, help="new mode-0700 acquisition directory")
    args = parser.parse_args(argv)
    acquiring = args.policy is not None or args.supplemental_zip is not None
    supplemental = any(
        value is not None
        for value in (
            args.supplemental_zip,
            args.validate_supplemental,
            args.discard_supplemental,
        )
    )
    if acquiring != (args.output is not None):
        parser.error("--output is required only for acquisition actions")
    if supplemental != (args.supplemental_policy is not None):
        parser.error("--supplemental-policy is required only for supplemental actions")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.discard_candidate is not None:
            removed = discard_candidate_texts(args.discard_candidate)
            print(
                json.dumps(
                    {
                        "candidate_manifest": str(args.discard_candidate),
                        "private_text_files_removed": removed,
                        "private_text_retained": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.validate_supplemental is not None:
            manifest = validate_supplemental_candidate(
                args.validate_supplemental, args.supplemental_policy
            )
            print(
                json.dumps(
                    {
                        "archive_sha256": manifest["archive"]["sha256"],
                        "member_text_files_created": manifest[
                            "member_text_files_created"
                        ],
                        "operator_archive_preserved": True,
                        "selected_entries": manifest["selected_entry_count"],
                        "unique_reviewed_cases": manifest["unique_reviewed_cases"],
                        "valid": True,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.discard_supplemental is not None:
            removed = discard_supplemental_candidate(
                args.discard_supplemental, args.supplemental_policy
            )
            print(
                json.dumps(
                    {
                        "metadata_files_removed": removed,
                        "operator_archive_preserved": True,
                        "supplemental_text_files_removed": 0,
                        "supplemental_text_retained": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.supplemental_zip is not None:
            output = args.output.resolve(strict=False)
            manifest = acquire_supplemental_zip(
                args.supplemental_zip,
                args.supplemental_policy,
                output,
            )
            print(
                json.dumps(
                    {
                        "archive_sha256": manifest["archive"]["sha256"],
                        "artifact_status": manifest["artifact_status"],
                        "code_executions": manifest["code_executions"],
                        "member_text_files_created": manifest[
                            "member_text_files_created"
                        ],
                        "operator_archive_preserved": True,
                        "output": str(output),
                        "policy_review_status": manifest["policy_review_status"],
                        "selected_entries": manifest["selected_entry_count"],
                        "third_party_code_executions": manifest[
                            "third_party_code_executions"
                        ],
                        "unique_reviewed_cases": manifest["unique_reviewed_cases"],
                    },
                    sort_keys=True,
                )
            )
            return 0
        policy_path = args.policy
        policy_raw = read_regular_bytes(policy_path, "source policy", MAX_POLICY_BYTES)
        policy = validate_policy(load_json_bytes(policy_raw, "source policy", MAX_POLICY_BYTES))
        output = args.output.resolve(strict=False)
        manifest = Acquirer(policy, GitHubClient(), output, sha256_bytes(policy_raw)).acquire()
        print(
            json.dumps(
                {
                    "output": str(output),
                    "artifact_status": manifest["artifact_status"],
                    "policy_review_status": manifest["policy_review_status"],
                    "repositories": manifest["repository_count"],
                    "runnable": manifest["policy_review_status"] == "approved",
                    "sources": manifest["source_count"],
                    "unique_content_hashes": manifest["unique_content_hashes"],
                    "unique_semantic_cases": manifest["unique_semantic_cases"],
                },
                sort_keys=True,
            )
        )
        return 0
    except (ContractError, OSError) as exc:
        print(f"ACQUISITION FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
