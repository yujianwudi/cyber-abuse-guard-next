#!/usr/bin/env python3
"""Fail closed on repository-local credentials and identifying host metadata.

The scanner inventories Git-visible files, rejects sensitive filenames before
reading content, and never opens restricted evaluation/holdout paths. Findings
contain only a rule name and location; matched values are never printed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Iterable, Sequence


MAX_SCAN_BYTES = 8 * 1024 * 1024
ALLOW_MARKER = re.compile(
    r"repo-secret-scan:\s*allow(?:\s+[A-Za-z0-9_.:-]+)+", re.IGNORECASE
)
RESTRICTED_PATH = re.compile(
    r"(?:^|/)[^/]*(?:evaluation|holdout|consumed|private|blind|retired)[^/]*(?:/|$)",
    re.IGNORECASE,
)
ROUND9_INDEPENDENT_PATH = re.compile(
    r"^testdata/round9-independent-(?:benign|malicious)-v[0-9]+(?:/|$)",
    re.IGNORECASE,
)
SSH_KEY_BASENAMES = frozenset(
    {
        "id_ed25519",
        "id_ed25519.pub",
        "id_ed25519_servers",
        "id_ed25519_servers.pub",
        "id_rsa",
        "id_rsa.pub",
        "id_dsa",
        "id_dsa.pub",
        "id_ecdsa",
        "id_ecdsa.pub",
    }
)
SECRET_SUFFIXES = frozenset({".ppk", ".p12", ".pfx", ".jks", ".keystore"})
SECRET_EXACT_NAMES = frozenset({".env", ".netrc", ".npmrc"})
PUBLIC_IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")


def _private_key_pattern() -> re.Pattern[str]:
    fence = "-" * 5
    return re.compile(
        re.escape(fence + "BEGIN ")
        + r"(?:OPENSSH |RSA |EC |DSA |PGP )?"
        + re.escape("PRIVATE KEY" + fence)
    )


CONTENT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key-material", _private_key_pattern()),
    (
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    ("openai-api-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-live-key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b")),
    (
        "credential-bearing-url",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", re.IGNORECASE),
    ),
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str


def normalize_relative_path(value: str) -> str:
    normalized = PurePosixPath(value.replace("\\", "/")).as_posix()
    parts = PurePosixPath(normalized).parts
    if (
        normalized in {"", "."}
        or normalized.startswith("/")
        or any(part == ".." for part in parts)
    ):
        raise ValueError(f"repository path is not relative: {value!r}")
    return normalized


def is_restricted_path(relative: str) -> bool:
    return bool(RESTRICTED_PATH.search(relative) or ROUND9_INDEPENDENT_PATH.search(relative))


def path_findings(relative: str) -> list[Finding]:
    basename = PurePosixPath(relative).name.lower()
    suffix = PurePosixPath(relative).suffix.lower()
    findings: list[Finding] = []
    if relative == ".round9-local-sandbox" or relative.startswith(".round9-local-sandbox/"):
        findings.append(Finding(relative, 0, "local-sandbox-path"))
    if basename in SSH_KEY_BASENAMES:
        findings.append(Finding(relative, 0, "ssh-key-filename"))
    if suffix in SECRET_SUFFIXES:
        findings.append(Finding(relative, 0, "secret-container-filename"))
    if basename in SECRET_EXACT_NAMES or (
        basename.startswith(".env.") and basename != ".env.example"
    ):
        findings.append(Finding(relative, 0, "secret-config-filename"))
    return findings


def line_findings(relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER.search(line):
            continue
        for rule, pattern in CONTENT_RULES:
            if pattern.search(line):
                findings.append(Finding(relative, line_number, rule))
        for match in PUBLIC_IPV4.finditer(line):
            try:
                address = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            if address.version == 4 and address.is_global:
                findings.append(Finding(relative, line_number, "public-ipv4-metadata"))
    return findings


def _read_regular_file(path: Path) -> tuple[bytes | None, str | None]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, "unreadable-or-link-path"
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None, "non-regular-path"
        data = os.read(descriptor, MAX_SCAN_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_SCAN_BYTES:
        return None, "oversized-unscanned-file"
    return data, None


def scan_paths(root: Path, relative_paths: Iterable[str]) -> list[Finding]:
    root = root.resolve(strict=True)
    findings: list[Finding] = []
    seen: set[str] = set()
    for raw_relative in relative_paths:
        relative = normalize_relative_path(raw_relative)
        if relative in seen:
            continue
        seen.add(relative)
        if is_restricted_path(relative):
            continue  # restricted paths are never opened
        findings.extend(path_findings(relative))
        candidate = root.joinpath(*PurePosixPath(relative).parts)
        if not candidate.exists() and not candidate.is_symlink():
            continue
        data, read_error = _read_regular_file(candidate)
        if read_error is not None:
            findings.append(Finding(relative, 0, read_error))
            continue
        assert data is not None
        if b"\x00" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(line_findings(relative, text))
    return sorted(set(findings))


def git_visible_paths(root: Path) -> list[str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("Git-visible path inventory failed") from exc
    if completed.returncode != 0:
        raise RuntimeError("Git-visible path inventory failed")
    return [
        entry.decode("utf-8", "surrogateescape")
        for entry in completed.stdout.split(b"\0")
        if entry
    ]


def run(root: Path) -> int:
    try:
        findings = scan_paths(root, git_visible_paths(root))
    except (OSError, RuntimeError, ValueError):
        print("repository secret scan could not inspect the Git-visible tree", file=sys.stderr)
        return 2
    if findings:
        print(f"repository secret scan failed with {len(findings)} finding(s)", file=sys.stderr)
        for finding in findings:
            location = f"{finding.path}:{finding.line}" if finding.line else finding.path
            print(f"{location}: {finding.rule}", file=sys.stderr)
        return 1
    print("repository secret scan passed")
    return 0


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    return run(args.root)


if __name__ == "__main__":
    raise SystemExit(main())
