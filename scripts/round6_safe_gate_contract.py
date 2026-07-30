#!/usr/bin/env python3
"""Fail closed when Round6 entrypoints escape the privacy-safe command graph.

The checker audits workflow run blocks, reachable Make recipes, shell scripts,
and Python scripts. It validates names and paths before opening files and never
reads restricted evaluation, holdout, private, blind, retired, or consumed data.
"""

from __future__ import annotations

import _imp
import argparse
import ast
import hashlib
import re
import shlex
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


def reject_repository_yaml_shadow(repository_root: Path, search_path: list[str]) -> None:
    repository_root = repository_root.resolve()
    for raw_entry in search_path:
        entry = Path(raw_entry or ".").resolve()
        try:
            entry.relative_to(repository_root)
        except ValueError:
            continue
        shadow_names = (
            "yaml.py",
            "yaml.pyc",
            "yaml",
            *(f"yaml{suffix}" for suffix in _imp.extension_suffixes()),
        )
        for relative in shadow_names:
            candidate = entry / relative
            if candidate.exists() or candidate.is_symlink():
                raise RuntimeError(
                    f"repository-local PyYAML shadow is forbidden: {candidate}"
                )


_REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
reject_repository_yaml_shadow(_REPOSITORY_ROOT, sys.path)
import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import (
    AliasToken,
    AnchorToken,
    DirectiveToken,
    DocumentEndToken,
    DocumentStartToken,
    FlowMappingStartToken,
    FlowSequenceStartToken,
    KeyToken,
    TagToken,
)

try:
    Path(yaml.__file__).resolve().relative_to(_REPOSITORY_ROOT)
except ValueError:
    pass
else:
    raise RuntimeError("PyYAML must resolve outside the repository")


RESTRICTED_PATH_MARKERS = (
    "consumed",
    "evaluation",
    "holdout",
    "private",
    "blind",
    "retired",
)
REVIEWED_RESTRICTED_MARKER_SOURCE_PATHS = frozenset(
    {
        "scripts/round9_external_evaluation_contract.py",
        "scripts/round9_external_evaluation_contract_test.py",
    }
)
FORBIDDEN_TARGETS = {
    "consumed-boundary-test",
    "formal-release",
    "format-check",
    "git-diff-check",
    "holdout-test",
    "module-verify",
    "package-release",
    "package-source-release",
    "release",
    "release-doc-consistency",
    "release-doc-consistency-test",
    "release-evidence",
    "release-preflight",
    "reproducibility-test",
    "script-test",
    "verification-fault-test",
    "verify-release",
    "vet",
    "vulncheck",
}
FORBIDDEN_SCRIPT_NAME = re.compile(
    r"^(?:formal-release|generate-release-evidence|package-release|"
    r"package-source-release|release-doc-consistency|release-preflight|"
    r"release-verification-fault-test|reproducibility-test|verify-release)\.sh$",
    re.IGNORECASE,
)
FORBIDDEN_TARGET_NAME = re.compile(
    r"(?:consumed|evaluation|holdout|private|blind|retired)", re.IGNORECASE
)
TARGET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.%/-]*$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
SCRIPT_REFERENCE = re.compile(
    r"(?:^|[^A-Za-z0-9_.-])(scripts/[A-Za-z0-9_./-]+\.(?:sh|py))"
)
SHELL_OPERATORS = {"&&", "||", ";", "|", "&"}
SAFE_DYNAMIC_TOOL_VARIABLES = {"go_bin", "cyclonedx"}
REPOSITORY_WORKFLOW_DISPATCH_INPUT_LIMIT = 10
ACTIVE_WORKFLOW_PATHS = (
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/policy-gate.yml",
)
ACTIONLINT_VERSION = "v1.7.12"
ACTIONLINT_CONFIG_PATH = ".github/actionlint.yaml"
ACTIONLINT_CONFIG_TEXT = (
    "self-hosted-runner:\n"
    "  labels: []\n"
)
ACTIONLINT_COMMAND = (
    "$(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION) "
    + " ".join(ACTIVE_WORKFLOW_PATHS)
)
WORKFLOW_DIRECTORY_AUXILIARY_PATHS = (".github/workflows/README.md",)
ACTIVE_RC_WORKFLOW_PATH = ".github/workflows/release-rc.yml"
ROUND9_GATE_WORKFLOW_PATH = ".github/workflows/policy-gate.yml"
ROUND9_HOST_WORKFLOW_PATH = ".github/workflows/round9-host-validation.yml"
ROUND9_RC_WORKFLOW_PATH = ".github/workflows/round9-release-rc.yml"
ARCHIVED_RC_WORKFLOW_PATH = "docs/archive/workflows/release-rc-v0.15-rc.2.yml"
BLOCKED_PRERELEASE_MARKER = (
    "Attested prerelease - HOST, AUDIT, AND EVALUATION REQUIRED"
)
BLOCKED_PRERELEASE_INPUT_ORDER = (
    "tag",
    "expected_commit",
    "expected_tree",
    "ci_run_id",
    "candidate_run_id",
    "expected_so_sha256",
    "expected_store_zip_sha256",
    "external_attestations_json",
    "authorize_blocked_prerelease",
)
BLOCKED_PRERELEASE_INPUTS = set(BLOCKED_PRERELEASE_INPUT_ORDER)
BLOCKED_PRERELEASE_IF_LINES = (
    "if: >-",
    "fromJSON(inputs.external_attestations_json).host_validation == 'PASS' &&",
    "fromJSON(inputs.external_attestations_json).independent_audit_validation == 'PASS' &&",
    "fromJSON(inputs.external_attestations_json).independent_evaluation_validation == 'PASS' &&",
    "inputs.authorize_blocked_prerelease == true",
)
ADMISSION_INPUT_ENV = (
    "TAG: ${{ inputs.tag }}",
    "EXPECTED_COMMIT: ${{ inputs.expected_commit }}",
    "EXPECTED_TREE: ${{ inputs.expected_tree }}",
    "CI_RUN_ID: ${{ inputs.ci_run_id }}",
    "CANDIDATE_RUN_ID: ${{ inputs.candidate_run_id }}",
    "EXPECTED_SO_SHA256: ${{ inputs.expected_so_sha256 }}",
    "EXPECTED_STORE_ZIP_SHA256: ${{ inputs.expected_store_zip_sha256 }}",
    "DISPATCH_REF: ${{ github.ref }}",
    "DISPATCH_SHA: ${{ github.sha }}",
    "WORKFLOW_REF: ${{ github.workflow_ref }}",
    "WORKFLOW_SHA: ${{ github.workflow_sha }}",
    "EXTERNAL_ATTESTATIONS_JSON: ${{ inputs.external_attestations_json }}",
    "AUTHORIZED: ${{ inputs.authorize_blocked_prerelease }}",
)
ADMISSION_INPUT_COMMANDS = (
    '[[ "$TAG" =~ ^v0\\.15-dev\\.round6([.][0-9]+)?$ ]]',
    '[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]]',
    '[[ "$EXPECTED_TREE" =~ ^[0-9a-f]{40}$ ]]',
    '[[ "$CI_RUN_ID" =~ ^[1-9][0-9]*$ ]]',
    '[[ "$CANDIDATE_RUN_ID" =~ ^[1-9][0-9]*$ ]]',
    '[[ "$EXPECTED_SO_SHA256" =~ ^[0-9a-f]{64}$ ]]',
    '[[ "$EXPECTED_STORE_ZIP_SHA256" =~ ^[0-9a-f]{64}$ ]]',
    '[[ "$DISPATCH_REF" == "refs/tags/$TAG" ]]',
    '[[ "$DISPATCH_SHA" == "$EXPECTED_COMMIT" ]]',
    '[[ "$WORKFLOW_SHA" == "$EXPECTED_COMMIT" ]]',
    '[[ "$WORKFLOW_REF" == "${GITHUB_REPOSITORY}/.github/workflows/attested-prerelease.yml@refs/tags/$TAG" ]]',
    '[[ "$AUTHORIZED" == true ]]',
    "jq -e '",
    '  type == "object" and',
    "  (keys == [",
    '    "host_evidence_sha256",',
    '    "host_validation",',
    '    "independent_audit_sha256",',
    '    "independent_audit_validation",',
    '    "independent_evaluation_id",',
    '    "independent_evaluation_sha256",',
    '    "independent_evaluation_validation"',
    "  ]) and",
    '  ([.[] | type] | all(. == "string")) and',
    '  .host_validation == "PASS" and',
    '  (.host_evidence_sha256 | test("^[0-9a-f]{64}$")) and',
    '  .independent_audit_validation == "PASS" and',
    '  (.independent_audit_sha256 | test("^[0-9a-f]{64}$")) and',
    '  .independent_evaluation_validation == "PASS" and',
    '  (.independent_evaluation_id | test("^evaluation-v(1[1-9]|[2-9][0-9]|[1-9][0-9]{2,})$")) and',
    '  (.independent_evaluation_sha256 | test("^[0-9a-f]{64}$"))',
    "' <<<\"$EXTERNAL_ATTESTATIONS_JSON\" >/dev/null",
)
ADMISSION_CI_ENV = (
    "CI_RUN_ID: ${{ inputs.ci_run_id }}",
    "EXPECTED_COMMIT: ${{ inputs.expected_commit }}",
    "GH_TOKEN: ${{ github.token }}",
)
ADMISSION_CI_COMMANDS = (
    'response="$(mktemp)"',
    'trap \'rm -f -- "$response"\' EXIT',
    "curl --fail-with-body --silent --show-error --location \\",
    "  --header 'Accept: application/vnd.github+json' \\",
    '  --header "Authorization: Bearer $GH_TOKEN" \\',
    "  --header 'X-GitHub-Api-Version: 2022-11-28' \\",
    '  "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/actions/runs/${CI_RUN_ID}" \\',
    '  --output "$response"',
    "jq -e \\",
    '  --arg run_id "$CI_RUN_ID" \\',
    '  --arg repository "$GITHUB_REPOSITORY" \\',
    '  --arg expected_commit "$EXPECTED_COMMIT" \\',
    "  '(.id | tostring) == $run_id and",
    '   .name == "CI" and',
    '   .path == ".github/workflows/ci.yml" and',
    '   .event == "push" and',
    '   .head_sha == $expected_commit and',
    '   .status == "completed" and',
    '   .conclusion == "success" and',
    "   .repository.full_name == $repository' \\",
    '  "$response" >/dev/null',
)
CANDIDATE_ADMISSION_ENV = (
    "CANDIDATE_RUN_ID: ${{ inputs.candidate_run_id }}",
    "EXPECTED_COMMIT: ${{ inputs.expected_commit }}",
    "GH_TOKEN: ${{ github.token }}",
)
CANDIDATE_ADMISSION_COMMANDS = (
    'response="$(mktemp)"',
    'trap \'rm -f -- "$response"\' EXIT',
    "curl --fail-with-body --silent --show-error --location \\",
    "  --header 'Accept: application/vnd.github+json' \\",
    '  --header "Authorization: Bearer $GH_TOKEN" \\',
    "  --header 'X-GitHub-Api-Version: 2022-11-28' \\",
    '  "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/actions/runs/${CANDIDATE_RUN_ID}" \\',
    '  --output "$response"',
    "jq -e \\",
    '  --arg run_id "$CANDIDATE_RUN_ID" \\',
    '  --arg repository "$GITHUB_REPOSITORY" \\',
    '  --arg expected_commit "$EXPECTED_COMMIT" \\',
    "  '(.id | tostring) == $run_id and",
    '   .name == "Candidate build - NOT A RELEASE" and',
    '   .path == ".github/workflows/candidate.yml" and',
    '   .event == "workflow_dispatch" and',
    '   .head_sha == $expected_commit and',
    '   .status == "completed" and',
    '   .conclusion == "success" and',
    "   .repository.full_name == $repository' \\",
    '  "$response" >/dev/null',
)
SAFE_GATE_COMMANDS = (
    "python3 -B scripts/round6_safe_gate_contract.py --root .",
)
ROUND9_SAFE_GATE_COMMANDS = (
    "/usr/bin/python3 -I -B scripts/round6_safe_gate_contract.py --root .",
)
ROUND9_SAFE_GATE_BOOTSTRAP_COMMANDS = (
    "set -euo pipefail",
    'libyaml_package="$RUNNER_TEMP/libyaml-0-2_0.2.5-1_amd64.deb"',
    'pyyaml_package="$RUNNER_TEMP/python3-yaml_6.0-3+b2_amd64.deb"',
    "curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 "
    "--output \"$libyaml_package\" "
    "'https://deb.debian.org/debian/pool/main/liby/libyaml/"
    "libyaml-0-2_0.2.5-1_amd64.deb'",
    "printf '%s  %s\\n' "
    "'207b539919a47c85bcf738677f0ccf5bbac9844f2d3f158696f518be4c4ba6c4' "
    '"$libyaml_package" | sha256sum -c -',
    '[[ "$(stat -c \'%s\' "$libyaml_package")" == 53580 ]]',
    '[[ "$(dpkg-deb -f "$libyaml_package" Package)" == libyaml-0-2 ]]',
    '[[ "$(dpkg-deb -f "$libyaml_package" Version)" == 0.2.5-1 ]]',
    '[[ "$(dpkg-deb -f "$libyaml_package" Architecture)" == amd64 ]]',
    "curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 "
    "--output \"$pyyaml_package\" "
    "'https://deb.debian.org/debian/pool/main/p/pyyaml/"
    "python3-yaml_6.0-3+b2_amd64.deb'",
    "printf '%s  %s\\n' "
    "'8d0db0b3099298fe039b94e4c52a6987798a90d23b80de3ac13c3cb75cf622a2' "
    '"$pyyaml_package" | sha256sum -c -',
    'dpkg -i "$libyaml_package"',
    'dpkg -i "$pyyaml_package"',
    '[[ "$(dpkg-query -W -f=\'${Version}\' libyaml-0-2)" == 0.2.5-1 ]]',
    '[[ "$(dpkg-query -W -f=\'${Architecture}\' libyaml-0-2)" == amd64 ]]',
    '[[ "$(dpkg-query -W -f=\'${Version}\' python3-yaml)" == \'6.0-3+b2\' ]]',
    '[[ "$(dpkg-query -W -f=\'${Architecture}\' python3-yaml)" == amd64 ]]',
    "/usr/bin/python3 -I -B - <<'PY'",
    "import pathlib",
    "import yaml",
    'assert pathlib.Path(yaml.__file__).resolve() == pathlib.Path("/usr/lib/python3/dist-packages/yaml/__init__.py")',
    'assert yaml.__version__ == "6.0"',
    "PY",
    'rm -f -- "$libyaml_package" "$pyyaml_package"',
)
SAFE_WORKFLOW_ENV_LINES = {
    "GOTOOLCHAIN: go1.26.4",
    "GOFLAGS: -mod=readonly",
    "GO_VERSION: '1.26.4'",
    "VERSION: '0.15'",
    "RC_VERSION: '0.15-rc.4'",
    "CYCLONEDX_GOMOD_VERSION: 'v1.9.0'",
    "GOVULNCHECK_VERSION: 'v1.6.0'",
    "ROUND9_BENIGN_MANIFEST_SHA256: d33e4ff8954741a2fe9c24c0d34b239c649c7e0a6d31463cddba84dc6b6580b8",
    "ROUND9_BENIGN_CASES_SHA256: 36d7f4dd635710f7ee81d02f9f62502c6276e554c80fc852f3d40acbfa70688d",
    "ROUND9_PAIRED_MANIFEST_SHA256: 29d84900edeec8fceceee9ccd2640571f1e962643931f388dcc842b058c6a2c2",
    "ROUND9_PAIRED_CASES_SHA256: 2a30da8d4872029d9b070a7b8bd8fb72a132994a21975f64b49cd56ecf4b2b3d",
    "ROUND9_PAIRED_LABEL_AUDIT_SHA256: a2d34853f20ae1c0b18690a4f58f100fe0014c53232457d5084aa90407e2ab8f",
}
SAFE_WORKFLOW_ENV = {
    "GOTOOLCHAIN": "go1.26.4",
    "GOFLAGS": "-mod=readonly",
    "GO_VERSION": "1.26.4",
    "VERSION": "0.15",
    "RC_VERSION": "0.15-rc.4",
    "CYCLONEDX_GOMOD_VERSION": "v1.9.0",
    "GOVULNCHECK_VERSION": "v1.6.0",
    "ROUND9_BENIGN_MANIFEST_SHA256": "d33e4ff8954741a2fe9c24c0d34b239c649c7e0a6d31463cddba84dc6b6580b8",
    "ROUND9_BENIGN_CASES_SHA256": "36d7f4dd635710f7ee81d02f9f62502c6276e554c80fc852f3d40acbfa70688d",
    "ROUND9_PAIRED_MANIFEST_SHA256": "29d84900edeec8fceceee9ccd2640571f1e962643931f388dcc842b058c6a2c2",
    "ROUND9_PAIRED_CASES_SHA256": "2a30da8d4872029d9b070a7b8bd8fb72a132994a21975f64b49cd56ecf4b2b3d",
    "ROUND9_PAIRED_LABEL_AUDIT_SHA256": "a2d34853f20ae1c0b18690a4f58f100fe0014c53232457d5084aa90407e2ab8f",
}
DANGEROUS_WORKFLOW_ENV = re.compile(
    r"^(?:BASH_ENV|ENV|PATH|CDPATH|GLOBIGNORE|PROMPT_COMMAND|SHELLOPTS|BASHOPTS|"
    r"LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|PYTHONPATH|PYTHONHOME|PERL5OPT|RUBYOPT|"
    r"NODE_OPTIONS|GIT_CONFIG_[A-Z0-9_]+)$"
)
CLEAN_EXECUTION_ENV = (
    ("BASH_ENV", ""),
    ("ENV", ""),
    ("PATH", "/usr/bin:/bin"),
    ("CDPATH", ""),
    ("GLOBIGNORE", ""),
    ("PROMPT_COMMAND", ""),
    ("LD_PRELOAD", ""),
    ("LD_LIBRARY_PATH", ""),
    ("LD_AUDIT", ""),
    ("PYTHONPATH", ""),
    ("PYTHONHOME", ""),
    ("PERL5OPT", ""),
    ("RUBYOPT", ""),
    ("NODE_OPTIONS", ""),
    ("NODE_PATH", ""),
    ("GIT_CONFIG_COUNT", "0"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_ASKPASS", "/bin/false"),
    ("SSH_ASKPASS", "/bin/false"),
    ("GIT_SSH_COMMAND", "/bin/false"),
    ("CURL_HOME", "/nonexistent"),
    ("GH_CONFIG_DIR", "/nonexistent"),
    ("HTTP_PROXY", ""),
    ("HTTPS_PROXY", ""),
    ("ALL_PROXY", ""),
)
CLEAN_EXECUTION_ENV_MAP = dict(CLEAN_EXECUTION_ENV)
CLEAN_EXECUTION_ENV_PATHS = {
    "jobs.verify.steps[12].env",
    "jobs.verify.steps[13].env",
}
CPA_MODULE_PATH = "github.com/router-for-me/CLIProxyAPI/v7"
CPA_ROUND8_VERSION = "v7.2.95"
CPA_ROUND8_COMMIT = "f71ec0eb6776854457892452cf28c47f0d658251"
CPA_CURRENT_VERSION = "v7.2.109"
CPA_CURRENT_COMMIT = "928478e4b91533cec05a763bfac3edad9c3e76cf"
CPA_CURRENT_MODULE_SUM = "h1:AM6nizpKiBkIr2ZSQ+XUwz1vkNTGoxSRlrTkt5hdLG8="
CPA_CURRENT_GO_MOD_SUM = "h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ="
BLOCKED_TOP_LEVEL_KEYS = (
    "name",
    "on",
    "permissions",
    "concurrency",
    "env",
    "jobs",
)
BLOCKED_JOB_KEYS = {
    "admission": ("runs-on", "timeout-minutes", "steps"),
    "verify": ("needs", "permissions", "runs-on", "timeout-minutes", "steps"),
    "publish": (
        "needs",
        "environment",
        "if",
        "permissions",
        "runs-on",
        "timeout-minutes",
        "steps",
    ),
}
BLOCKED_STEP_CONTRACTS = {
    "admission": (
        (
            "Fail closed unless every external gate and authorization is explicit",
            ("name", "env", "run"),
            None,
        ),
        (
            "Bind admission to a successful CI run for the exact commit",
            ("name", "env", "run"),
            None,
        ),
        (
            "Bind admission to the successful clean-candidate run",
            ("name", "env", "run"),
            None,
        ),
    ),
    "verify": (
        (
            "Checkout the explicitly supplied existing tag",
            ("name", "uses", "with"),
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        ),
        ("Recheck the Round6 restricted-data boundary", ("name", "run"), None),
        (
            "Verify immutable source identity and annotated tag",
            ("name", "env", "run"),
            None,
        ),
        (
            "Set up pinned Go",
            ("name", "uses", "with"),
            "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
        ),
        ("Install bounded build dependencies", ("name", "run"), None),
        (
            "Download the exact Host-tested clean candidate artifact",
            ("name", "uses", "with"),
            "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        ),
        (
            "Verify candidate manifest and Host-tested artifact bytes",
            ("name", "env", "run"),
            None,
        ),
        ("Run source and Round6 regression gates", ("name", "run"), None),
        (
            f"Verify pinned CPA {CPA_ROUND8_VERSION} source compatibility",
            ("name", "env", "run"),
            None,
        ),
        (
            "Rebuild the exact clean Host-tested candidate",
            ("name", "env", "run"),
            None,
        ),
        (
            "Prove clean candidate reproducibility against root artifacts",
            ("name", "env", "run"),
            None,
        ),
        ("Recheck source cleanliness", ("name", "run"), None),
        (
            "Reverify source and artifact identity before transfer",
            ("name", "env", "run"),
            None,
        ),
        (
            "Upload exact verified blocked-development artifacts",
            ("name", "uses", "env", "with"),
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ),
    ),
    "publish": (
        (
            "Download exact verified blocked-development artifacts",
            ("name", "uses", "with"),
            "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        ),
        (
            "Reverify transferred artifact identity without a repository token",
            ("name", "env", "run"),
            None,
        ),
        (
            "Upload immutable blocked-attestation artifact for the formal workflow",
            ("name", "uses", "with"),
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ),
        (
            "Recheck immutable tag and create draft blocked prerelease",
            ("name", "env", "run"),
            None,
        ),
    ),
}
BLOCKED_ALLOWED_GITHUB_TOKEN_PATHS = {
    "jobs.admission.steps[1].env.GH_TOKEN",
    "jobs.admission.steps[2].env.GH_TOKEN",
    "jobs.verify.steps[5].with.github-token",
    "jobs.publish.steps[3].env.GH_TOKEN",
}
BLOCKED_ALLOWED_GITHUB_IDENTITY_EXPRESSIONS = {
    "jobs.admission.steps[0].env.DISPATCH_REF": "${{ github.ref }}",
    "jobs.admission.steps[0].env.DISPATCH_SHA": "${{ github.sha }}",
    "jobs.admission.steps[0].env.WORKFLOW_REF": "${{ github.workflow_ref }}",
    "jobs.admission.steps[0].env.WORKFLOW_SHA": "${{ github.workflow_sha }}",
    "jobs.verify.steps[5].with.repository": "${{ github.repository }}",
    "jobs.publish.steps[1].env.WORKFLOW_SHA": "${{ github.workflow_sha }}",
}
GITHUB_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
SENSITIVE_EXPRESSION_CONTEXT = re.compile(r"(?i)(?<![A-Za-z0-9_])(?:github|secrets)(?![A-Za-z0-9_])")
ROUND6_SPARSE_PATTERNS = (
    "/*",
    "!/.round9-local-sandbox/**",
    "!/cmd/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*",
    "!/cmd/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*",
    "!/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*",
    "!/cmd/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*",
    "!/cmd/**/*[Bb][Ll][Ii][Nn][Dd]*",
    "!/cmd/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*",
    "!/docs/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*",
    "!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*",
    "!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]_[Rr][Ee][Pp][Oo][Rr][Tt].[Mm][Dd]",
    "!/docs/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*",
    "!/docs/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*",
    "!/docs/**/*[Bb][Ll][Ii][Nn][Dd]*",
    "!/docs/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*",
    "!/internal/classifier/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*",
    "!/internal/classifier/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*",
    "!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*",
    "!/internal/classifier/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*",
    "!/internal/classifier/**/*[Bb][Ll][Ii][Nn][Dd]*",
    "!/internal/classifier/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*",
    "!/testdata/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*",
    "!/testdata/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*",
    "!/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*",
    "!/testdata/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*",
    "!/testdata/**/*[Bb][Ll][Ii][Nn][Dd]*",
    "!/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*",
)
ROUND9_SPARSE_PATTERNS = (
    *ROUND6_SPARSE_PATTERNS[:23],
    "!/testdata/round9-independent-benign-v1/**",
    "!/testdata/round9-independent-malicious-v1/**",
    *ROUND6_SPARSE_PATTERNS[23:],
)
ROUND9_HOST_SPARSE_PATTERNS = ROUND9_SPARSE_PATTERNS
ROUND9_INDEPENDENT_GIT_PATHSPEC = ":(glob)testdata/round9-independent-*/**"
ROUND9_INDEPENDENT_GITIGNORE_LINES = (
    "/testdata/round9-independent-benign-v1/",
    "/testdata/round9-independent-malicious-v1/",
)
ROUND9_LOCAL_SECRET_GITIGNORE_LINES = (
    "*.ppk",
    "id_ed25519",
    "id_ed25519_servers",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "/.round9-local-sandbox/",
)


def reviewed_sparse_pattern_options(source: Path) -> tuple[tuple[str, ...], ...]:
    if source.name == "ci.yml":
        # Synthetic unit fixtures retain the historical boundary; the real CI
        # validator below independently requires the Round 9 exclusions.
        return (ROUND6_SPARSE_PATTERNS, ROUND9_SPARSE_PATTERNS)
    if source.name in {"policy-gate.yml", "round9-gate.yml", "round9-release-rc.yml"}:
        return (ROUND9_SPARSE_PATTERNS,)
    if source.name == "round9-host-validation.yml":
        return (ROUND9_HOST_SPARSE_PATTERNS,)
    return (ROUND6_SPARSE_PATTERNS,)
SOURCE_RELEASE_EXCLUSION_CONTRACT_TEST_SCRIPT = (
    "scripts/source-release-exclusion-contract-test.sh"
)
SOURCE_RELEASE_EXCLUSION_CONTRACT_TEST_SHA256 = (
    "70254ba4224e4f45d6936bb0e63a6c7165ec71b11fbc3039ec0f2e02e7867c86"
)
SOURCE_RELEASE_SAFE_SHELL_FIXTURE_LINE = "  internal/config/id_rsa_policy.go; do"
SOURCE_RELEASE_SAFE_SCRIPT_PATH_FIXTURE_LINE = "  scripts/package-tar-gz.sh \\"
CONSUMED_BOUNDARY_LINES = {
    ".gitignore": ROUND9_INDEPENDENT_GITIGNORE_LINES
    + ROUND9_LOCAL_SECRET_GITIGNORE_LINES,
    ".gitattributes": (
        "/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]* export-ignore",
        "/docs/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]* export-ignore",
        "/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]* export-ignore",
        "/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]* export-ignore",
        "/testdata/round9-independent-*/** export-ignore",
        "/.round9-local-sandbox/** export-ignore",
    ),
    "scripts/release-common.sh": (
        '  local path="${1,,}"',
        '  case "$path" in',
        "    cmd/*evaluation*|cmd/*holdout*|cmd/*consumed*|cmd/*private*|cmd/*blind*|cmd/*retired*|\\",
        "    docs/*consumed*|docs/*private*|docs/*blind*|docs/*retired*|\\",
        "    internal/classifier/*consumed*|internal/classifier/*private*|internal/classifier/*blind*|internal/classifier/*retired*|\\",
        "    testdata/*evaluation*|testdata/*holdout*|testdata/*consumed*|testdata/*private*|testdata/*blind*|testdata/*retired*)",
    ),
    "scripts/package-source-release.sh": (
        "  ':(exclude,glob).round9-local-sandbox/**'",
        "  ':(exclude,glob,icase)cmd/**/*consumed*'",
        "  ':(exclude,glob,icase)docs/**/*consumed*'",
        "  ':(exclude,glob,icase)internal/classifier/**/*consumed*'",
        "  ':(exclude,glob,icase)testdata/**/*consumed*'",
        "secret_key_path_pattern='(^|/)(id_(ed25519|ed25519_servers|rsa|dsa|ecdsa)(\\.pub)?|[^/]*\\.ppk)($|/)'",
        "local_sandbox_path_pattern='(^|/)\\.round9-local-sandbox($|/)'",
        "if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<\"$listing\"; then",
    ),
    "Makefile": (
        "\t\t':(exclude,glob,icase)cmd/**/*consumed*' \\",
        "\t\t':(exclude,glob,icase)docs/**/*consumed*' \\",
        "\t\t':(exclude,glob,icase)internal/classifier/**/*consumed*' \\",
        "\t\t':(exclude,glob,icase)testdata/**/*consumed*' \\",
        "\tpython3 -B ./scripts/repository_secret_scan_test.py",
        "\tpython3 -B ./scripts/repository_secret_scan.py --root .",
    ),
    "scripts/repository_secret_scan.py": (
        "def is_restricted_path(relative: str) -> bool:",
        "        if is_restricted_path(relative):",
        "            continue  # restricted paths are never opened",
        "        data, read_error = _read_regular_file(candidate)",
        '            print(f"{location}: {finding.rule}", file=sys.stderr)',
    ),
    SOURCE_RELEASE_EXCLUSION_CONTRACT_TEST_SCRIPT: (
        "tracked_independent=\"$(git -C \"$root\" ls-files -- \\",
        "  ':(glob)testdata/round9-independent-*/**')\"",
        '  release_die "independent corpus plaintext is tracked in Git history: $tracked_independent"',
        "tracked_local_sensitive=\"$(git -C \"$root\" ls-files -- \\",
        '  release_die "local sandbox or SSH key material is tracked in Git history: $tracked_local_sensitive"',
        '    release_die "restricted local path is not protected by .gitignore: $path"',
        "  cmd/safe/nested-consumed",
        "  cmd/safe/nested-Consumed",
        "  cmd/safe/nested-Evaluation/payload.go",
        "  cmd/safe/nested-Consumed/payload.go",
        "  cmd/safe/nested-HoldOut/payload.go",
        "  docs/safe/nested-Private/report.md",
        "  internal/classifier/safe/nested-Blind/payload.go",
        "  testdata/safe/nested-Retired/payload.json",
        "  .round9-local-sandbox/synthetic-note.txt",
        "  '!/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'",
        "  '!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'",
        "  '!/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'",
        "  '!/testdata/round9-independent-*/**'",
        "  '!/.round9-local-sandbox/**'",
        'git -C "$sparse_fixture" sparse-checkout set --no-cone "${sparse_patterns[@]}"',
        "verifier_path='scripts/round9_external_evaluation_contract.py'",
        "verifier_sha256='43f5df13a6f805e65d7289f5b327c3af2f7d75511a833667e388ec24b2a5262b'",
        "verifier_test_path='scripts/round9_external_evaluation_contract_test.py'",
        "verifier_test_sha256='7f32dc75f6354777eadf8791cc3b56ba9f9ac8db37334b8a66c7d046ded7ba48'",
        'verifier_sha="$(tar -xOf "$archive" "$verifier_path" | sha256sum | awk \'{print $1}\')"',
        'verifier_test_sha="$(tar -xOf "$archive" "$verifier_test_path" | sha256sum | awk \'{print $1}\')"',
        "if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<\"$restricted_listing\"; then",
        "transient_path_pattern='(^|/)(classifier_(candidate|single)_[^/]*|[^/]*\\.(cpu|mem|pprof|test\\.exe|exe))($|/)'",
        "test_binary_path_pattern='(^|/)[^/]*\\.test($|/)'",
        "safe_test_source_pattern='(^|/)Dockerfile\\.test($|/)'",
        "backup_binary_archive_path_pattern='(^|/)[^/]*\\.(bak|backup|so|dll|zip|tar|tgz|gz)($|/)'",
        "secret_key_path_pattern='(^|/)(id_(ed25519|ed25519_servers|rsa|dsa|ecdsa)(\\.pub)?|[^/]*\\.ppk)($|/)'",
        "local_sandbox_path_pattern='(^|/)\\.round9-local-sandbox($|/)'",
        'expected_archive_guard="  local backup_binary_archive_path_pattern=\'$backup_binary_archive_path_pattern\'"',
        'grep -Fxq "$expected_archive_guard" "$root/scripts/round6-rc-artifacts.sh" ||',
        'grep -Fxq Dockerfile.test <<<"$listing" || \\',
        "  classifier.accept.cpu \\",
        "  profiles/classifier.mem \\",
        "  profiles/heap.pprof \\",
        "  classifier.test \\",
        "  classifier.test.exe \\",
        "  tools/probe.exe \\",
        "  classifier_candidate_exact \\",
        "  tmp/classifier_candidate_fixed \\",
        "  classifier_single_fixed \\",
        "  tmp/classifier_single_tree/member.go \\",
        "  audit.db.pre-v5-20260722T000000.000000000Z.bak \\",
        "  snapshots/audit.backup \\",
        "  plugins/cyber-abuse-guard.so \\",
        "  plugins/cyber-abuse-guard.dll \\",
        "  release/package.zip \\",
        "  release/source.tar \\",
        "  release/source.tar.gz \\",
        "  release/source.tgz \\",
        "  release/transcript.gz \\",
        "  keys/operator.ppk \\",
        "  .round9-local-sandbox/cache.txt; do",
        "  internal/classifier/profile.cpu.go \\",
        "  internal/classifier/package.test.go \\",
        "  internal/classifier/windows.exe.go \\",
        "  internal/classifier/classifier_candidate.go \\",
        "  internal/classifier/classifier_single.go \\",
        "  internal/plugin/cyber-abuse-guard.so.go \\",
        "  internal/platform/provider.dll.go \\",
        "  internal/audit/migration_backup_test.go \\",
        "  docs/archive.zip.md \\",
        "  testdata/fixture.tar.json \\",
        "  scripts/package-tar-gz.sh \\",
        "  docs/id_ed25519.md \\",
        SOURCE_RELEASE_SAFE_SHELL_FIXTURE_LINE,
        'is_forbidden_source_archive_path() {',
        '  grep -Eiq "$backup_binary_archive_path_pattern" <<<"$path" && return 0',
        '  grep -Eiq "$transient_path_pattern" <<<"$path" && return 0',
        '  grep -Eiq "$secret_key_path_pattern" <<<"$path" && return 0',
        '  grep -Eiq "$local_sandbox_path_pattern" <<<"$path" && return 0',
        '  if grep -Eiq "$test_binary_path_pattern" <<<"$path" &&',
        '    ! grep -Eiq "$safe_test_source_pattern" <<<"$path"; then',
        '  is_forbidden_source_archive_path "cyber-abuse-guard-fixture/$path" || \\',
        '  if is_forbidden_source_archive_path "cyber-abuse-guard-fixture/$path"; then',
    ),
    "scripts/round6-safe-go-files.sh": (
        '  case "${file,,}" in',
        "    internal/classifier/*evaluation*|internal/classifier/*holdout*|internal/classifier/*consumed*|internal/classifier/*private*|internal/classifier/*retired*|internal/classifier/*blind*)",
    ),
}
ROUND6_REPRODUCIBILITY_SCRIPT_SHA256 = (
    "7a49d38a291c78e48a89b2d3573efc063d634a2a9f1d9b8d88c775993caf600a"
)
ROUND6_REPRODUCIBILITY_ENTRY_MODE_CONTRACT = """reproducibility_mode="${ROUND6_REPRODUCIBILITY_MODE:-release}"
case "$reproducibility_mode" in
  development)
    [[ "${RELEASE_CANDIDATE_BUILD:-0}" == 0 ]] || \\
      release_die "development reproducibility mode cannot enable candidate builds"
    ALLOW_DIRTY_BUILD=1
    ;;
  release) ;;
  *) release_die "ROUND6_REPRODUCIBILITY_MODE must be release or development" ;;
esac"""
ROUND6_REPRODUCIBILITY_MODE_CONTRACT = """case "$RELEASE_BUILD_KIND" in
  candidate)
    release_assert_candidate_build
    clone_dirty_build=0
    clone_candidate_build=1
    artifact_version="$RELEASE_SOURCE_VERSION"
    ;;
  formal)
    release_assert_tag
    release_assert_formal_build
    clone_dirty_build=0
    artifact_version="$RELEASE_SOURCE_VERSION"
    ;;
  development) ;;
  *) release_die "unsupported Round6 reproducibility build kind: $RELEASE_BUILD_KIND" ;;
esac"""
ROUND6_REPRODUCIBILITY_FORMAL_PACKAGE_COMMAND = (
    '    env "${common_env[@]}" "$clone/scripts/package-release.sh"'
)
ROUND6_REPRODUCIBILITY_PACKAGE_BRANCH_CONTRACT = """  if [[ "$RELEASE_BUILD_KIND" == formal ]]; then
    env "${common_env[@]}" "$clone/scripts/package-release.sh"
  else
    PLUGIN_BINARY="$clone/dist/$so" \\
      STORE_ARCHIVE="$clone/dist/$store_zip" \\
      SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH" \\
      "$clone/scripts/create-store-archive.sh"
  fi"""
ROUND6_REPRODUCIBILITY_CHECKSUMS_CONTRACT = (
    '        sbom.cdx.json >checksums.txt',
    '      sha256sum -c checksums.txt',
    'compare_artifact "checksums manifest" checksums.txt',
    '  for relative in "$so" "$so.sha256" "$store_zip" build-metadata.json checksums.txt \\',
)
BLOCKED_STEP_RUN_SHA256 = {
    ("admission", 0): "e687f6dfcf81b226a179502e0e078696ab8da5ed66797f30fe7cf19e59b83013",
    ("admission", 1): "7f1817ec7b567df4be63fafd9ee2b2347ac37e01982e41ee3338f64c79cae81a",
    ("admission", 2): "26030928c867d579089d1e69fcba37ff65433ca93697835abdda4f6365f2e4e5",
    ("verify", 1): "739ebd378c0da4e32117344b43258da8bb85a61590c8966c47dce26274df75cc",
    ("verify", 2): "3427df1bdbbcd38976514b679706f45fe6331981e750168beffd9bfdd1efdea1",
    ("verify", 4): "5e3a856d2482d7781379962364756c3c536e214b21c3fa92e75f5148e31e4168",
    ("verify", 6): "86252b49e4b21673adafab187e650b9a051cb28dd78c5d7a91d4d52ad951586d",
    ("verify", 7): "feb84636bac16fb6245913190b0803f0644ee094423c531ad4e59c752e6bc9fd",
    ("verify", 8): "fa50af5a75fcdd76f7a5c0900c3f983b2ee285220229e1746c35671713cba7b7",
    ("verify", 9): "eabde1048cd0f10bfc3540f427c3674b3cf8d5fc0206bebc58e695a328dbb0cb",
    ("verify", 10): "d6bd0b9f43ef190a6545893891fe514928b3e354a438f357602e2d3a89565bd0",
    ("verify", 11): "72ba08821693dcb100be3d4dcfaac32d485191186d46fa22119ae7a7b60990b9",
    ("verify", 12): "25116143b78146e257b7eb89c5466266132755433249c07664c0cdbf01944c7d",
    ("publish", 1): "cb81f05abebca1df12d9075de1009a6a92874b850d1c2628f31ebcb1127209b5",
    ("publish", 3): "c9054c7b8a4a819a778420abf66f71138c77f5c2ffe975c2830f56cf66a5cf7d",
}
BLOCKED_STEP_RUN_STYLE = {
    ("admission", 0): "|",
    ("admission", 1): "|",
    ("admission", 2): "|",
    ("verify", 1): "|",
    ("verify", 2): "|",
    ("verify", 4): "|",
    ("verify", 6): "|",
    ("verify", 7): "|",
    ("verify", 8): None,
    ("verify", 9): None,
    ("verify", 10): None,
    ("verify", 11): None,
    ("verify", 12): "|",
    ("publish", 1): "|",
    ("publish", 3): "|",
}
BLOCKED_STEP_ENV = {
    ("admission", 0): (
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("CANDIDATE_RUN_ID", "${{ inputs.candidate_run_id }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("EXPECTED_STORE_ZIP_SHA256", "${{ inputs.expected_store_zip_sha256 }}"),
        ("DISPATCH_REF", "${{ github.ref }}"),
        ("DISPATCH_SHA", "${{ github.sha }}"),
        ("WORKFLOW_REF", "${{ github.workflow_ref }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
        ("EXTERNAL_ATTESTATIONS_JSON", "${{ inputs.external_attestations_json }}"),
        ("AUTHORIZED", "${{ inputs.authorize_blocked_prerelease }}"),
    ),
    ("admission", 1): (
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("GH_TOKEN", "${{ github.token }}"),
    ),
    ("admission", 2): (
        ("CANDIDATE_RUN_ID", "${{ inputs.candidate_run_id }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("GH_TOKEN", "${{ github.token }}"),
    ),
    ("verify", 2): (
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
    ),
    ("verify", 6): (
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("CANDIDATE_RUN_ID", "${{ inputs.candidate_run_id }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("EXPECTED_STORE_ZIP_SHA256", "${{ inputs.expected_store_zip_sha256 }}"),
    ),
    ("verify", 8): (("CPA_COMPAT_VERIFY_REMOTE", "1"),),
    ("verify", 9): (
        ("RELEASE_CANDIDATE_BUILD", "1"),
        ("RELEASE_CANDIDATE_EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("RELEASE_CANDIDATE_EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("ROUND6_SAFE_SPARSE_BUILD", "1"),
        ("REQUIRE_DIST_ARTIFACTS", "1"),
    ),
    ("verify", 10): (
        ("RELEASE_CANDIDATE_BUILD", "1"),
        ("RELEASE_CANDIDATE_EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("RELEASE_CANDIDATE_EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("ROUND6_SAFE_SPARSE_BUILD", "1"),
    ),
    ("verify", 12): (
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("EXPECTED_STORE_ZIP_SHA256", "${{ inputs.expected_store_zip_sha256 }}"),
    )
    + CLEAN_EXECUTION_ENV,
    ("verify", 13): CLEAN_EXECUTION_ENV,
    ("publish", 1): (
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("EXPECTED_STORE_ZIP_SHA256", "${{ inputs.expected_store_zip_sha256 }}"),
        ("TAG", "${{ inputs.tag }}"),
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("CANDIDATE_RUN_ID", "${{ inputs.candidate_run_id }}"),
        ("HOST_EVIDENCE_SHA256", "${{ fromJSON(inputs.external_attestations_json).host_evidence_sha256 }}"),
        ("INDEPENDENT_AUDIT_SHA256", "${{ fromJSON(inputs.external_attestations_json).independent_audit_sha256 }}"),
        ("INDEPENDENT_EVALUATION_ID", "${{ fromJSON(inputs.external_attestations_json).independent_evaluation_id }}"),
        ("INDEPENDENT_EVALUATION_SHA256", "${{ fromJSON(inputs.external_attestations_json).independent_evaluation_sha256 }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    ),
    ("publish", 3): (
        ("GH_TOKEN", "${{ github.token }}"),
        ("TAG", "${{ inputs.tag }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("EXPECTED_SO_SHA256", "${{ inputs.expected_so_sha256 }}"),
        ("EXPECTED_STORE_ZIP_SHA256", "${{ inputs.expected_store_zip_sha256 }}"),
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("CANDIDATE_RUN_ID", "${{ inputs.candidate_run_id }}"),
        ("HOST_EVIDENCE_SHA256", "${{ fromJSON(inputs.external_attestations_json).host_evidence_sha256 }}"),
        ("INDEPENDENT_AUDIT_SHA256", "${{ fromJSON(inputs.external_attestations_json).independent_audit_sha256 }}"),
        ("INDEPENDENT_EVALUATION_ID", "${{ fromJSON(inputs.external_attestations_json).independent_evaluation_id }}"),
        ("INDEPENDENT_EVALUATION_SHA256", "${{ fromJSON(inputs.external_attestations_json).independent_evaluation_sha256 }}"),
    ),
}

CANDIDATE_WORKFLOW_NAME = "Candidate build - NOT A RELEASE"
CANDIDATE_INPUT_ORDER = (
    "expected_commit",
    "expected_tree",
    "ci_run_id",
    "authorize_clean_candidate",
)
CANDIDATE_TOP_LEVEL_KEYS = (
    "name",
    "on",
    "permissions",
    "concurrency",
    "env",
    "jobs",
)
CANDIDATE_JOB_KEYS = {
    "admission": ("runs-on", "timeout-minutes", "steps"),
    "build": ("needs", "permissions", "runs-on", "timeout-minutes", "steps"),
}
CANDIDATE_STEP_CONTRACTS = {
    "admission": (
        (
            "Bind dispatch to the exact main tip and candidate workflow",
            ("name", "env", "run"),
            None,
        ),
        (
            "Bind candidate admission to successful exact-head push CI",
            ("name", "env", "run"),
            None,
        ),
    ),
    "build": (
        (
            "Checkout exact Round6-safe source",
            ("name", "uses", "with"),
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        ),
        ("Recheck restricted-data and workflow contracts", ("name", "run"), None),
        ("Verify immutable source identity", ("name", "env", "run"), None),
        (
            "Set up pinned Go",
            ("name", "uses", "with"),
            "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
        ),
        ("Install bounded candidate dependencies", ("name", "run"), None),
        (
            f"Recheck source, regressions, and pinned CPA {CPA_ROUND8_VERSION} contract",
            ("name", "env", "run"),
            None,
        ),
        (
            "Build exact clean unreleased Host-test assets",
            ("name", "env", "run"),
            None,
        ),
        (
            "Rebuild candidate in two clean clones and compare bytes",
            ("name", "env", "run"),
            None,
        ),
        (
            "Reverify candidate identity and source cleanliness",
            ("name", "env", "run"),
            None,
        ),
        (
            "Upload private exact-commit candidate",
            ("name", "uses", "with"),
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ),
    ),
}
CANDIDATE_STEP_RUN_SHA256 = {
    ("admission", 0): "5213ecde1d5f26b4e9d8c31ab926eea06959c8dcb3d696551417dbf350bbbe7b",
    ("admission", 1): "7f1817ec7b567df4be63fafd9ee2b2347ac37e01982e41ee3338f64c79cae81a",
    ("build", 1): "739ebd378c0da4e32117344b43258da8bb85a61590c8966c47dce26274df75cc",
    ("build", 2): "8966c407a8e05f9a88182c2130b24b907e58dd1d874d55fe4f86c9bfedef6457",
    ("build", 4): "2f78c328a7b32ffa36c614f564c4aad5665013494e5838bb8b34fbc7a4d792bd",
    ("build", 5): "43a1e2b51527edd141c9b4c53ac0c11775f0b8b9948054e5d2f329221a555e60",
    ("build", 6): "f99bfc855f5afa25f227afce3800b41093b1858f9ae4b8027378ebf530470cf8",
    ("build", 7): "d6bd0b9f43ef190a6545893891fe514928b3e354a438f357602e2d3a89565bd0",
    ("build", 8): "841d631459baa6ee68b3021816c7d9da6310be1527d4c01a66a546210e288289",
}
CANDIDATE_STEP_RUN_STYLE = {
    ("admission", 0): "|",
    ("admission", 1): "|",
    ("build", 1): "|",
    ("build", 2): "|",
    ("build", 4): "|",
    ("build", 5): "|",
    ("build", 6): None,
    ("build", 7): None,
    ("build", 8): "|",
}
CANDIDATE_STEP_ENV = {
    ("admission", 0): (
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("AUTHORIZED", "${{ inputs.authorize_clean_candidate }}"),
        ("DISPATCH_REF", "${{ github.ref }}"),
        ("DISPATCH_SHA", "${{ github.sha }}"),
        ("WORKFLOW_REF", "${{ github.workflow_ref }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    ),
    ("admission", 1): (
        ("CI_RUN_ID", "${{ inputs.ci_run_id }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("GH_TOKEN", "${{ github.token }}"),
    ),
    ("build", 2): (
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
    ),
    ("build", 5): (("CPA_COMPAT_VERIFY_REMOTE", "1"),),
    ("build", 6): (
        ("RELEASE_CANDIDATE_BUILD", "1"),
        ("RELEASE_CANDIDATE_EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("RELEASE_CANDIDATE_EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("RELEASE_CANDIDATE_WORKFLOW_SHA", "${{ github.workflow_sha }}"),
        ("ROUND6_SAFE_SPARSE_BUILD", "1"),
        ("REQUIRE_DIST_ARTIFACTS", "1"),
    ),
    ("build", 7): (
        ("RELEASE_CANDIDATE_BUILD", "1"),
        ("RELEASE_CANDIDATE_EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("RELEASE_CANDIDATE_EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("ROUND6_SAFE_SPARSE_BUILD", "1"),
    ),
    ("build", 8): (
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
    ),
}
CANDIDATE_ALLOWED_GITHUB_TOKEN_PATHS = {
    "jobs.admission.steps[1].env.GH_TOKEN",
}
CANDIDATE_ALLOWED_GITHUB_IDENTITY_EXPRESSIONS = {
    "jobs.admission.steps[0].env.DISPATCH_REF": "${{ github.ref }}",
    "jobs.admission.steps[0].env.DISPATCH_SHA": "${{ github.sha }}",
    "jobs.admission.steps[0].env.WORKFLOW_REF": "${{ github.workflow_ref }}",
    "jobs.admission.steps[0].env.WORKFLOW_SHA": "${{ github.workflow_sha }}",
    "jobs.build.steps[6].env.RELEASE_CANDIDATE_WORKFLOW_SHA": "${{ github.workflow_sha }}",
}
CI_ALLOWED_GITHUB_IDENTITY_EXPRESSIONS = {
    "concurrency.group": "${{ github.workflow }}-${{ github.ref }}",
}
CANDIDATE_ARTIFACTS = (
    "dist/cyber-abuse-guard-v0.15.so",
    "dist/cyber-abuse-guard-v0.15.so.sha256",
    "dist/cyber-abuse-guard_0.15_linux_amd64.zip",
    "dist/build-metadata.json",
    "dist/checksums.txt",
    "dist/ruleset-manifest.json",
    "dist/ruleset.sha256",
    "dist/sbom.cdx.json",
    "dist/candidate-manifest.json",
)
CANDIDATE_SCRIPT_SHA256 = {
    "round6-candidate-artifacts.sh": "8a12c39c951ec8d15673946124558635f9809492729480fc421750d1564d59ab",
    "release-candidate-contract-test.sh": "61ebbe72f0062c3f5b0ccfc7df4f0ab3b85594b43561cd1926fe87b602d92a90",
}
RC_RELEASE_SCRIPT_SHA256 = "9d3704144468e89777ea75d40c27dc8bc932b1d05a2084117e938a0ec368d6e3"
RELEASE_BUILD_METADATA_SCRIPT = "scripts/release-build-metadata.sh"
RELEASE_BUILD_METADATA_SCRIPT_SHA256 = (
    "6d5312459fd238f35ddbdee6c79779cb340fba4029f49f7f6490b64f639a259c"
)
RC_BUILDER_IMAGE = "docker.io/library/golang:1.26.4-bookworm"
RC_BUILDER_IMAGE_DIGEST = (
    "sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b"
)
RC_BUILDER_REFERENCE = f"{RC_BUILDER_IMAGE}@{RC_BUILDER_IMAGE_DIGEST}"
RC_REPRODUCIBLE_RUNNER_NAME = "UNRECORDED_EPHEMERAL_GITHUB_HOSTED_RUNNER"
RC_REPRODUCIBLE_WORKFLOW_RUN = "UNRECORDED_EPHEMERAL_GITHUB_ACTIONS_RUN"
RC_REPRODUCIBLE_WORKFLOW_ATTEMPT = "UNRECORDED_EPHEMERAL_GITHUB_ACTIONS_ATTEMPT"
RC_PROVENANCE_ACTION = (
    "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373"
)
RC_SOURCE_ARCHIVE_TRANSIENT_PATH_PATTERN = (
    r"(^|/)(classifier_(candidate|single)_[^/]*|[^/]*\.(cpu|mem|pprof|test\.exe|exe))($|/)"
)
RC_SOURCE_ARCHIVE_TEST_BINARY_PATH_PATTERN = r"(^|/)[^/]*\.test($|/)"
RC_SOURCE_ARCHIVE_SAFE_TEST_SOURCE_PATTERN = r"(^|/)Dockerfile\.test($|/)"
RC_SOURCE_ARCHIVE_BACKUP_BINARY_ARCHIVE_PATH_PATTERN = (
    r"(^|/)[^/]*\.(bak|backup|so|dll|zip|tar|tgz|gz)($|/)"
)
RC_SOURCE_ARCHIVE_SECRET_KEY_PATH_PATTERN = (
    r"(^|/)(id_(ed25519|ed25519_servers|rsa|dsa|ecdsa)(\.pub)?|[^/]*\.ppk)($|/)"
)
RC_SOURCE_ARCHIVE_LOCAL_SANDBOX_PATH_PATTERN = r"(^|/)\.round9-local-sandbox($|/)"
RC_SOURCE_ARCHIVE_FORBIDDEN_PATH_FIXTURES = (
    "classifier.accept.cpu",
    "profiles/classifier.mem",
    "profiles/heap.pprof",
    "classifier.test",
    "classifier.test.exe",
    "tools/probe.exe",
    "classifier_candidate_exact",
    "tmp/classifier_candidate_fixed",
    "classifier_single_fixed",
    "tmp/classifier_single_tree/member.go",
    "audit.db.pre-v5-20260722T000000.000000000Z.bak",
    "snapshots/audit.backup",
    "plugins/cyber-abuse-guard.so",
    "plugins/cyber-abuse-guard.dll",
    "release/package.zip",
    "release/source.tar",
    "release/source.tar.gz",
    "release/source.tgz",
    "release/transcript.gz",
    "id_ed25519",
    "keys/id_ed25519.pub",
    "nested/id_ed25519_servers",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "keys/operator.ppk",
    ".round9-local-sandbox/cache.txt",
)
RC_SOURCE_ARCHIVE_SAFE_PATH_FIXTURES = (
    "Dockerfile.test",
    "integration/fixture/Dockerfile.test",
    "internal/classifier/profile.cpu.go",
    "internal/classifier/memory.mem.go",
    "internal/classifier/trace.pprof.go",
    "internal/classifier/package.test.go",
    "internal/classifier/windows.exe.go",
    "internal/classifier/classifier_candidate.go",
    "internal/classifier/classifier_single.go",
    "internal/classifier/classifier.candidate_test.go",
    "internal/classifier/classifier_test.go",
    "docs/classifier-candidate-notes.md",
    "internal/audit/state.bak.go",
    "docs/database.backup.md",
    "internal/plugin/cyber-abuse-guard.so.go",
    "internal/platform/provider.dll.go",
    "docs/archive.zip.md",
    "testdata/fixture.tar.json",
    "docs/source.tgz.md",
    "docs/transcript.gz.txt",
    "scripts/package-tar-gz.sh",
    "docs/id_ed25519.md",
    "internal/config/id_rsa_policy.go",
)
RC_SOURCE_ARCHIVE_TRANSIENT_GUARD_BLOCK = f'''  if grep -Eiq "$backup_binary_archive_path_pattern" <<<"$listing" ||
    grep -Eiq "$transient_path_pattern" <<<"$listing" ||
    {{ grep -Ei "$test_binary_path_pattern" <<<"$listing" |
        grep -Eiv "$safe_test_source_pattern" >/dev/null; }}; then
    rm -f -- "$temporary"
    release_die "RC source archive contains a forbidden backup, binary, archive, profile, test executable, or temporary classifier candidate"
  fi'''
RC_SOURCE_ARCHIVE_SECRET_GUARD_BLOCK = '''  if grep -Eiq '(^|/)(\\.git($|/)|dist($|/)|build($|/)|[^/]*\\.(db|sqlite|sqlite3|key|pem|p12|pfx|jks|keystore|log)($|[-.])|\\.env($|[./]))' <<<"$listing" ||
    grep -Eiq "$secret_key_path_pattern" <<<"$listing" ||
    grep -Eiq "$local_sandbox_path_pattern" <<<"$listing"; then
    rm -f -- "$temporary"
    release_die "RC source archive contains a forbidden repository, build, database, secret, local sandbox, or log path"
  fi'''
ACTIVE_RC_WORKFLOW_SHA256 = "7f418cef8a0e405ed98b4324d607b7578762066d816c97009e1db7b3bf287740"
ROUND8_HOST_WORKFLOW_SHA256 = "0dafb17a7189abd07dabc5e45ff0e35ef4787f69defdcb5096f947aee0dec551"
ROUND9_GATE_WORKFLOW_SHA256 = "b1d2b4c226444ca4e86c177936e6b6a351c091633945d967aa8f8d1a8962864d"
ROUND9_HOST_WORKFLOW_SHA256 = "701ebfc27dcbcdc9adff9c9887c1eaa6af8ac959602ade0613624d363e2edf17"
ROUND9_RC_WORKFLOW_SHA256 = "09ab4e5dedb90ffbfe8f2436c8dc7ee6353162dc825e9751c708bdca68c800e1"
ROUND9_INDEPENDENT_AUDIT_SCRIPT = "scripts/round9_independent_audit_contract.py"
ROUND9_INDEPENDENT_AUDIT_TEST_SCRIPT = (
    "scripts/round9_independent_audit_contract_test.py"
)
ROUND9_INDEPENDENT_AUDIT_REVIEWED_SCRIPT_SHA256 = {
    ROUND9_INDEPENDENT_AUDIT_SCRIPT: (
        "b8e4d8803b9f692bcf49efd074efdc8092cffad303068737e2c2c9b0f36021a7"
    ),
    ROUND9_INDEPENDENT_AUDIT_TEST_SCRIPT: (
        "f32ff6e257e8ea1cd1a1d8a713d7ac762a860faf2a297f7ea519a717f7e6b84e"
    ),
}
ROUND9_MACHINE_REPORT_SCRIPT = "scripts/round9_machine_reports.py"
ROUND9_MACHINE_REPORT_SCRIPT_SHA256 = (
    "89e7b48edcc41c87bb0f59a7f365b3d103176371eeac75078042e56faeb8bb9d"
)
ROUND9_MACHINE_REPORT_COMMAND_FUNCTION_AST_CONTRACT = (
    2,
    "a99b170a154d4da1f523e53f89c48b5fc402dec5bf105a652028626cff0155a9",
)
ROUND9_MACHINE_REPORT_TEST_SCRIPT = "scripts/round9_machine_reports_test.py"
ROUND9_MACHINE_REPORT_TEST_SCRIPT_SHA256 = (
    "9e5c855a5612a36727383e0f21b547c41651684b17f6b5026473d04ef2a18e1f"
)
ROUND9_MACHINE_REPORT_TEST_SUBPROCESS_CONTRACT = (
    1,
    "3f1c0bbe522604663df5d54bfac8858af0f5a0ec69d5314d13c682c4cef3c68b",
)
REPOSITORY_SECRET_SCAN_SCRIPT = "scripts/repository_secret_scan.py"
REPOSITORY_SECRET_SCAN_TEST_SCRIPT = "scripts/repository_secret_scan_test.py"
REPOSITORY_SECRET_SCAN_SHA256 = {
    REPOSITORY_SECRET_SCAN_SCRIPT: (
        "1eb092a3edd00ef7889fb62e015f946d7ea5942d0ebaf3368d375d1a3718a5e3"
    ),
    REPOSITORY_SECRET_SCAN_TEST_SCRIPT: (
        "78b11d3a062f88364c5712642086d62c80dbd35e76eab49f238f46a336ab857b"
    ),
}
RC_RELEASE_WORKFLOW_SHA256 = "5ff480e2bb84bc33da81cc4e9839e4bca50453fc7e77debc1f24dd5b04362107"
RC_RELEASE_INPUT_ORDER = (
    "tag",
    "expected_tag_object_sha",
    "expected_commit",
    "expected_tree",
    "ci_run",
    "publish_rc_release",
    "host_run",
    "host_artifact_id",
    "host_artifact_digest",
    "host_challenge",
)
ROUND8_HOST_INPUT_ORDER = (
    "tag",
    "expected_tag_object_sha",
    "expected_commit",
    "expected_tree",
    "phase1_run_id",
    "phase1_run_attempt",
    "phase1_artifact_id",
    "phase1_artifact_digest",
    "challenge",
)
ROUND9_HOST_INPUT_ORDER = (
    "tag",
    "expected_tag_object_sha",
    "expected_commit",
    "expected_tree",
    "phase1_run_id",
    "phase1_run_attempt",
    "phase1_artifact_id",
    "phase1_artifact_digest",
    "candidate_identity",
    "challenge",
)
ROUND9_RC_INPUT_ORDER = (
    "tag",
    "expected_tag_object_sha",
    "expected_commit",
    "expected_tree",
    "ci_run",
    "round9_gate_run",
    "host_run",
    "host_artifact_id",
    "host_artifact_digest",
    "host_challenge",
)
ROUND9_PRIVATE_ASSET_NAMES = frozenset(
    {
        "build-metadata.json",
        "checksums.txt",
        "cyber-abuse-guard-v0.16-rc.4.so",
        "cyber-abuse-guard-v0.16-rc.4.so.sha256",
        "cyber-abuse-guard_0.16-rc.4_linux_amd64.zip",
        "cyber-abuse-guard-v0.16-rc.4-audit-bundle.zip",
        "cyber-abuse-guard-v0.16-rc.4-source.tar.gz",
        "cyber-abuse-guard-v0.16-rc.4-source.tar.gz.sha256",
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
)
ROUND9_PUBLISHED_ASSET_NAMES = frozenset(
    {
        *ROUND9_PRIVATE_ASSET_NAMES,
        "round9-external-evaluation.json",
        "round9-external-ledger-proof.json",
    }
)
ROUND8_HOST_STEP_RUN_SHA256 = {
    0: "cf0e0747c306f15a56cf514951a354f9f0181643c34f86c53c851490b04467a1",
    2: "19063e73020ba868b7c1aa5c671ff8bc4a57ee882b0b3b369ebe66e0dbf0c99b",
    3: "afb1ed6f316cd0ed44d255d5f2974578aa096d83b6f356fa831aaccc7db51292",
    4: "4ee8615b3a29dc69434fad21141a73ff69234bd2b7628faeacd752dbd2802909",
    5: "415c1c9b58d8a951c76ac7ae0d5b317586140d0f64f4792d4838b9bb421ecf26",
    8: "ab7f3fce0627b6757de512d036583ecb2042000eaae1197d3167108b94dac926",
    9: "9a80a01795c411bd5bd269f49951765bd349a16b925c8027f5663d0e24d27c19",
}
ROUND8_BASE_STEP_RUN_SHA256 = {
    0: "083c67c86749f4f988952b912fd1eafa32b97998417d0cbcd4d1be423b71ecdf",
    1: "0d6ed073233abaa1e9b7849828fdc63b77166c35c6f4a15bf07a73437d6bfdb6",
}
CODEQL_WORKFLOW_SHA256 = "54cf0629dae660c38eaede7f726f6f396e007a1779fbc0032d99a9af440cd6d7"
FORMAL_OPERATION_SCRIPTS = (
    "formal-release.sh",
    "generate-release-evidence.sh",
    "package-release.sh",
    "package-source-release.sh",
    "release-preflight.sh",
    "verify-release.sh",
)
FORMAL_RELEASE_DOCUMENT_OVERRIDE_ENV = (
    "RELEASE_DOC_ROOT",
    "RELEASE_DOC_FIXTURE_MODE",
    "CURRENT_RELEASE_VERSION",
    "CURRENT_RULESET_SHA256",
    "CURRENT_CLASSIFIER_POLICY_VERSION",
    "CURRENT_CLASSIFIER_POLICY_SHA256",
)
FORMAL_RELEASE_ARTIFACTS = (
    "dist/cyber-abuse-guard-v0.15.so",
    "dist/cyber-abuse-guard-v0.15.so.sha256",
    "dist/cyber-abuse-guard_0.15_linux_amd64.zip",
    "dist/cyber-abuse-guard-v0.15-audit-bundle.zip",
    "dist/build-metadata.json",
    "dist/checksums.txt",
    "dist/ruleset-manifest.json",
    "dist/ruleset.sha256",
    "dist/sbom.cdx.json",
    "dist/release-test-summary.txt",
    "dist/release-test-summary.txt.sha256",
    "dist/release-evidence-final.md",
    "dist/release-evidence-final.md.sha256",
    "dist/cyber-abuse-guard-v0.15-source.tar.gz",
    "dist/cyber-abuse-guard-v0.15-source.tar.gz.sha256",
    "dist/round6-prerelease-attestation.json",
    "dist/round6-prerelease-attestation.json.sha256",
    "dist/formal-release-attestation.json",
    "dist/formal-release-attestation.json.sha256",
)
FORMAL_AUDIT_REPORT_PATH = "docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md"
FORMAL_RELEASE_STEP_RUN_SHA256 = {
    ("admission", 0): "c3ef443605630fdbd7379bb31e66ad8f36e154186ce61e77e1682bbdfb6ec996",
    ("build-and-verify", 2): "5bc38a90928a7309be0be55b3834ebf28c2eee7c2fd290ef19bf6d3a8dd3857d",
    ("build-and-verify", 3): "c3eb4a5705894448699eb404ef51cd796e735b8fd254324a66fc621d9571c1dd",
    ("build-and-verify", 4): "e2194c0fb1cc2681adff35d6c0a12e10540e17bb7495597ac1f3ccb992bbc53f",
    ("build-and-verify", 5): "309ed57fdbbe52e7410bc297e108cc94e42beda8790584ab20fae58107b01b2b",
    ("build-and-verify", 7): "2ecb4e3db81c81773248547deb2121bd998a7c1aeae69036485603c1760c53e2",
    ("build-and-verify", 8): "2824c61aa8a13293fe96c4a6f7586466ca90eb0f527182265f9be7df66586ccf",
    ("build-and-verify", 9): "85ab9b21007e3d06b5c4720274e1fe5753a3634b5611185736e4fc83b738dc38",
    ("build-and-verify", 10): "59019f683072911ccdd1638400fd5af145c9c6cbd8be29d8c75960b2fc888fbc",
    ("publish", 1): "ca29fccccf8950a2ddfa783c8420bc8be1b32dd75f790837c825af84b43eee0c",
    ("publish", 2): "1574a0d0ac458f3e12ab6052955d1027955a8cfad76f5773547da4d4bcb85fb2",
}
PROMOTE_STEP_RUN_SHA256 = {
    ("verify", 0): "1136924fac09486e80411376a74957eedba466120f9746dbf18636500b2a7f12",
    ("verify", 2): "81f3c306c6e57ff95c598cb10fcc9c9bd185361a1bb753ab98de0e4e4a8df813",
    ("promote", 0): "d04544c3a61f3bae7810179742dbd326ae291aa02791347eb4f2ebb5dfccd4b1",
}
REPRODUCIBILITY_WRAPPER_SCRIPT = "scripts/reproducibility-test.sh"
REPRODUCIBILITY_WRAPPER_SCRIPT_SHA256 = (
    "29bf44be67be80aea19f37acbbda01bba247b2319f32626b0f562ce9fda78824"
)
FROZEN_EVALUATION_TREE_SCRIPT = "scripts/verify-frozen-evaluation-v10-tree.sh"
FROZEN_EVALUATION_TREE_SCRIPT_SHA256 = (
    "a412d4c18e703945f176e6134dd5cebd515eafd7eb4872e84a35d00702b75bff"
)
FROZEN_EVALUATION_STATUS_COMMAND = (
    'status="$(git -C "$root" status --porcelain=v1 --untracked-files=all -- "${paths[@]}")"'
)
ROUND6_DOC_FIXTURE_WRAPPER_SCRIPT = "scripts/round6-doc-consistency-fixture-test.sh"
ROUND6_DOC_FIXTURE_WRAPPER_SCRIPT_SHA256 = (
    "037b83d204226b759d847782406c750f445b8869953320a2acae0d6e11d3a152"
)
ROUND6_DOC_FIXTURE_DEPENDENCY_SHA256 = {
    "scripts/release-doc-consistency-test.sh": "ae64a7a5c96d4d79d8b2bc216ae8601a331ca2e45a5927fd23d46191eac32a89",
    "scripts/release-doc-consistency.sh": "576e9f6b0e6ec23e0503c9101e67904d5ef28918d625afc0bf25425c8f0b077b",
}
ROUND6_PRIVACY_FIXTURE_SCRIPT = "scripts/release-evidence-privacy-test.sh"
ROUND6_PRIVACY_FIXTURE_SCRIPT_SHA256 = (
    "6306a733095173425ad735bea5d986de21ae2b3f4e6f053dee970d7436f9f762"
)
CPA_COMPAT_SCRIPT = "scripts/cpa-latest-compat.sh"
CPA_LATEST_RELEASE_API = (
    "https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest"
)
CPA_PINNED_MODULE_FILES = (
    ("go.mod", "go.sum", "primary"),
    (
        "integration/cpalatestcontract/go.mod",
        "integration/cpalatestcontract/go.sum",
        "primary",
    ),
    (
        "integration/pluginstorecontract/go.mod",
        "integration/pluginstorecontract/go.sum",
        "primary",
    ),
)
CPA_COMPAT_SCRIPT_SHA256 = (
    "c915c701470066dcdac616685bcb68c0890a03b0811abb08135bebab30d8b698"
)
CPA_COMPAT_FINAL_OUTPUT_CONTRACT = """if [[ "$verify_remote" == 1 ]]; then
  if [[ "$require_latest" == 1 ]]; then
    printf 'CPA pinned source/compile compatibility matrix PASS: profiles=%s remote_tag_verified=1 remote_latest_verified=1\\n' \\
      "${profiles[*]}"
  else
    printf 'CPA pinned source/compile compatibility matrix PASS: profiles=%s remote_tag_verified=1 remote_latest_check=SKIPPED_PINNED_TARGET\\n' \\
      "${profiles[*]}"
  fi
else
  printf 'CPA source/compile compatibility matrix PASS: profiles=%s remote_tag_check=SKIPPED remote_latest_check=SKIPPED\\n' \\
    "${profiles[*]}"
fi"""
EXTERNAL_ATTESTATION_SCRIPT_SHA256 = {
    "verify-external-release-attestation.sh": "25f0449f31a5f433fdd87c365242b1d03eea2d3f94b1e95df1762b993f895882",
    "verify-external-release-attestation-test.sh": "81968390b82a319944d151e3ac3834dd568cf48d6e17d444f9e297afab1408c8",
}
ROUND8_HOST_REVIEWED_SCRIPT_SHA256 = {
    "scripts/round8-build-host-images.sh": "734e33a429394a909a28df18afa45453b7c549430715605cc4ed1bbb46b8a55b",
    "scripts/round8-host-evidence.sh": "682c1edce5f546f42082e47177bb1e6817bffb7cfc5f4965dc0d495bda902a27",
    "scripts/round8-host-evidence-test.py": "92bd097fd7b58c066d0a2b95908ce2f176e6aa3ca998272d32b7b3011fab6574",
    "scripts/round8_host_evidence.py": "c603e856f1610ba687da81f61772fe4c04b6a20ed6ab13a59ddc81d36c0fc644",
    "scripts/round8_docker_sandbox.py": "30585beb793b7d35d842adce962fdc111eb76ef6a5ec963b6ab52470bbc64301",
}
ROUND9_EVAL_REVIEWED_SCRIPT_SHA256 = {
    "tools/round9-eval/cag_round9_cpa_sandbox_adapter.py": "d2ffad85eb62241a02f9549ccdb4f240445fbfe5636e262122a817c9071a650a",
    "tools/round9-eval/cag_round9_cpa_sandbox_adapter_test.py": "f287236bbcc19213fffb86af899384db5090ebd5083ef09256737a2b1329c77a",
    "tools/round9-eval/cag_round9_eval_broker.py": "7b41e3d9236e6e962591b04339494256299993fe2991f5daa196e024c5f2e768",
    "tools/round9-eval/cag_round9_eval_broker_test.py": "6bdb6f80f8e8a75c4202ec149178735756acfcb3a4fa5695cf5ed8fc5aa47a19",
    "tools/round9-eval/cag_round9_external_evaluator.py": "274d881defcf761e86f5e71fcf77300b60a9d54da37a605f4ebff0808f801610",
    "tools/round9-eval/cag_round9_external_evaluator_test.py": "86254e4f6492bf1f59fa2dd5ca0bc17a7e2dc1497341c27e02f9ad7ec11cf088",
    "tools/round9-eval/round9_eval_core.py": "a11385d70fd057629e38f0bee03d24eeaa30207ddf793c94f359854e68abf293",
    "tools/round9-eval/round9_eval_core_test.py": "5821d9016b8fa4b2c3c4fe6926dfaf4765c2c3173b126b11adfde52b99235bff",
    "tools/round9-eval/round9_eval_test_fixtures.py": "8b124e4c68f9576fa1d851bb86141a7d8bf3c216b8f41d3df2058dc2c7abfa62",
}
ROUND9_EVAL_SUBPROCESS_FUNCTION_CONTRACT = {
    "tools/round9-eval/cag_round9_cpa_sandbox_adapter.py": (
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    "tools/round9-eval/cag_round9_cpa_sandbox_adapter_test.py": (
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    "tools/round9-eval/cag_round9_eval_broker.py": (
        7,
        "217c672077bf01c668de2569f5bb7a179b357fbe0e6861f8eac7428728f24127",
    ),
    "tools/round9-eval/cag_round9_eval_broker_test.py": (
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    "tools/round9-eval/cag_round9_external_evaluator.py": (
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    "tools/round9-eval/cag_round9_external_evaluator_test.py": (
        2,
        "5abef5d748263f1a5023287fb6253abe789e70b10300d56ad0e9c772ddf816fe",
    ),
    "tools/round9-eval/round9_eval_core.py": (
        2,
        "49dcc001b67b7045eaf78d04ea77f9692fcb8283c9a3a774f44afd7fb34285d6",
    ),
    "tools/round9-eval/round9_eval_core_test.py": (
        2,
        "44f33f19c4bd05640c3cb0ec300f11992dd431d28fbdaefa38febb64958cd2c8",
    ),
    "tools/round9-eval/round9_eval_test_fixtures.py": (
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
}
ROUND9_EVAL_INSTALL_SCRIPT = "tools/round9-eval/install.sh"
ROUND9_EVAL_INSTALL_SCRIPT_SHA256 = (
    "99c851fb92d0e840ee6e1c0021890455743131b7882d47b12e5e09aa5fb1ee0d"
)
ROUND9_HOST_EVIDENCE_TEST_SCRIPT = "scripts/round9-host-evidence-test.py"
ROUND9_HOST_EVIDENCE_TEST_SCRIPT_SHA256 = (
    "87520bd1ca47ccf9f04cc3848a3a2d5a36114953daec915777e98fc74e5fa6a0"
)
ROUND9_HOST_EVIDENCE_TEST_SUBPROCESS_CONTRACT = (
    1,
    "489d132097ef6c0eb88d38578ea3a1cc5f0e52c8abcf9229d56edbf1e7831c5d",
)
ROUND9_HOST_EVIDENCE_SCRIPT = "scripts/round9_host_evidence.py"
ROUND9_HOST_EVIDENCE_SCRIPT_SHA256 = (
    "52a77e2501c3ae712af2895bdd283b2b45e351d20ce369f58404063e0f86cd75"
)
ROUND9_HOST_EVIDENCE_COMMAND_FUNCTION_CONTRACT = (
    1,
    18,
    "abf40b147b938d29c62e885dd56e8c6835d92dee3c374f4c3c3ff49b9b65c9d4",
)
ROUND9_DOCKER_SANDBOX_SCRIPT = "scripts/round9_docker_sandbox.py"
ROUND9_DOCKER_SANDBOX_SCRIPT_SHA256 = (
    "b1ed05981f2e443b23c752d388c8f09cf19bb86e0c480f051cf1bae9ee7fb1a4"
)
ROUND9_DOCKER_SANDBOX_SUBPROCESS_CONTRACT = (
    1,
    "29f706df26ec3fde1237d6120439a90737667768a770d15c8d0ec7956f17b90c",
)
ROUND9_MALICIOUS_TEXT_PRODUCER_STATIC_CLOSURE_SHA256 = {
    "internal/classifier/malicious_text_producer_inventory_test.go": (
        "e11969e711fc5a5c84fd0a7b5ba5317ba2bf6c2f4bf0aa33c5e4e8ac9d65ef88"
    ),
    "docs/reports/ROUND9_MALICIOUS_TEXT_PRODUCER_INVENTORY.json": (
        "def42b49e18fd373dbaa2730af9fc5006ba8c2c5a83e42984e78fa9c241e34aa"
    ),
}
ROUND6_SAFE_GATE_SCRIPT = "scripts/round6_safe_gate_contract.py"
ROUND6_SAFE_GATE_TEST_SCRIPT = "scripts/round6_safe_gate_contract_test.py"
ROUND6_SAFE_GATE_TEST_SHA256 = "7b8d05f42ee292c18058a74feb0dc376ee76c750f6aad3348eccdd0994d18c6a"
GENERATE_RELEASE_EVIDENCE_SCRIPT_SHA256 = "1ad76b2f44aa0d51a09a8b901ce11e73f1a417b26ad62382106291050682531d"


class ContractError(RuntimeError):
    pass


def validate_round9_malicious_text_producer_static_closure(root: Path) -> None:
    for relative, expected_hash in (
        ROUND9_MALICIOUS_TEXT_PRODUCER_STATIC_CLOSURE_SHA256.items()
    ):
        source = root / relative
        actual_hash = hashlib.sha256(read_regular_bytes(source, root)).hexdigest()
        if actual_hash != expected_hash:
            raise ContractError(
                "Round 9 malicious-text producer static-closure artifact "
                f"differs from the reviewed contract: {relative}"
            )


def validate_consumed_boundary_files(root: Path) -> None:
    for relative, required_lines in CONSUMED_BOUNDARY_LINES.items():
        source = root / relative
        lines = read_regular_text(source, root).splitlines()
        for required in required_lines:
            if lines.count(required) != 1:
                raise ContractError(
                    f"consumed exclusion boundary differs from the reviewed contract: {relative}"
                )
    source_release_test = root / SOURCE_RELEASE_EXCLUSION_CONTRACT_TEST_SCRIPT
    source_release_text = read_regular_text(source_release_test, root)
    if (
        hashlib.sha256(source_release_text.encode("utf-8")).hexdigest()
        != SOURCE_RELEASE_EXCLUSION_CONTRACT_TEST_SHA256
    ):
        raise ContractError(
            "consumed exclusion boundary differs from the reviewed contract: "
            + SOURCE_RELEASE_EXCLUSION_CONTRACT_TEST_SCRIPT
        )


def validate_round9_independent_git_boundary(root: Path) -> None:
    """Reject tracked independent-corpus paths without opening their contents."""

    command = [
        "git",
        "-C",
        str(root),
        "ls-files",
        "-z",
        "--",
        ROUND9_INDEPENDENT_GIT_PATHSPEC,
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise ContractError(
            "cannot verify the Round 9 independent Git boundary"
        ) from exc
    if completed.returncode != 0:
        raise ContractError("cannot verify the Round 9 independent Git boundary")
    if completed.stdout:
        paths = completed.stdout.rstrip(b"\0").split(b"\0")
        rendered = ", ".join(
            item.decode("utf-8", errors="backslashreplace") for item in paths[:4]
        )
        raise ContractError(
            "Round 9 independent corpus plaintext is tracked in Git history: " + rendered
        )


def yaml_location(node: Node | None, source: Path) -> str:
    if node is None:
        return f"{source}:missing"
    return f"{source}:{node.start_mark.line + 1}:{node.start_mark.column + 1}"


def validate_yaml_mapping_tree(node: Node, source: Path, path: str = "workflow") -> None:
    if isinstance(node, MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            if not isinstance(key_node, ScalarNode):
                raise ContractError(
                    f"workflow mapping keys must be plain scalars at {yaml_location(key_node, source)}"
                )
            if key_node.style is not None:
                raise ContractError(
                    f"workflow mapping keys may not be quoted or block-scalars at {yaml_location(key_node, source)}"
                )
            key = key_node.value
            if key in seen:
                raise ContractError(
                    f"workflow contains duplicate semantic key {key!r} at {yaml_location(key_node, source)}"
                )
            seen.add(key)
            validate_yaml_mapping_tree(value_node, source, f"{path}.{key}")
    elif isinstance(node, SequenceNode):
        for index, child in enumerate(node.value):
            validate_yaml_mapping_tree(child, source, f"{path}[{index}]")


def parse_workflow_yaml(text: str, source: Path) -> MappingNode:
    forbidden_tokens = (
        AliasToken,
        AnchorToken,
        DirectiveToken,
        DocumentEndToken,
        DocumentStartToken,
        FlowMappingStartToken,
        FlowSequenceStartToken,
        TagToken,
    )
    try:
        for token in yaml.scan(text, Loader=yaml.SafeLoader):
            if isinstance(token, forbidden_tokens):
                raise ContractError(
                    "workflow may not use YAML anchors, aliases, tags, directives, "
                    f"document markers, or flow collections at {source}:"
                    f"{token.start_mark.line + 1}:{token.start_mark.column + 1}"
                )
            if isinstance(token, KeyToken) and token.end_mark.index > token.start_mark.index:
                raise ContractError(
                    f"workflow may not use explicit YAML mapping keys at {source}:"
                    f"{token.start_mark.line + 1}:{token.start_mark.column + 1}"
                )
        document = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise ContractError(f"workflow is not valid fail-closed YAML: {source}: {exc}") from exc
    if not isinstance(document, MappingNode):
        raise ContractError(f"workflow root must be one YAML mapping: {source}")
    validate_yaml_mapping_tree(document, source)
    return document


def yaml_mapping(node: Node | None, source: Path, path: str) -> dict[str, Node]:
    if not isinstance(node, MappingNode):
        raise ContractError(f"workflow {path} must be a mapping at {yaml_location(node, source)}")
    return {key.value: value for key, value in node.value}


def yaml_mapping_keys(node: Node | None, source: Path, path: str) -> tuple[str, ...]:
    if not isinstance(node, MappingNode):
        raise ContractError(f"workflow {path} must be a mapping at {yaml_location(node, source)}")
    return tuple(key.value for key, _ in node.value)


def require_yaml_keys(
    node: Node | None, expected: tuple[str, ...], source: Path, path: str
) -> dict[str, Node]:
    actual = yaml_mapping_keys(node, source, path)
    if actual != expected:
        raise ContractError(
            f"workflow {path} keys/order changed: expected {expected}, got {actual}"
        )
    return yaml_mapping(node, source, path)


def yaml_sequence(node: Node | None, source: Path, path: str) -> list[Node]:
    if not isinstance(node, SequenceNode):
        raise ContractError(f"workflow {path} must be a sequence at {yaml_location(node, source)}")
    return list(node.value)


def yaml_scalar(node: Node | None, source: Path, path: str) -> str:
    if not isinstance(node, ScalarNode):
        raise ContractError(f"workflow {path} must be a scalar at {yaml_location(node, source)}")
    return node.value


def require_yaml_scalar(
    node: Node | None, expected: str, source: Path, path: str, *, tag: str | None = None
) -> None:
    actual = yaml_scalar(node, source, path)
    if actual != expected or (tag is not None and node.tag != tag):
        raise ContractError(
            f"workflow {path} must be exact scalar {expected!r}"
        )


def iter_yaml_scalars(node: Node, path: str = ""):
    if isinstance(node, MappingNode):
        for key_node, value_node in node.value:
            child_path = f"{path}.{key_node.value}" if path else key_node.value
            yield from iter_yaml_scalars(value_node, child_path)
    elif isinstance(node, SequenceNode):
        for index, child in enumerate(node.value):
            yield from iter_yaml_scalars(child, f"{path}[{index}]")
    elif isinstance(node, ScalarNode):
        yield path, node


def validate_sensitive_workflow_expressions(
    document: MappingNode,
    source: Path,
    *,
    allowed_token_paths: set[str],
    allowed_identity_expressions: dict[str, str],
) -> None:
    allowed_seen: set[str] = set()
    for path, node in iter_yaml_scalars(document):
        for match in GITHUB_EXPRESSION.finditer(node.value):
            expression = match.group(1).strip()
            if not SENSITIVE_EXPRESSION_CONTEXT.search(expression):
                continue
            if path in allowed_token_paths and node.value == "${{ github.token }}":
                allowed_seen.add(path)
                continue
            expected_identity = allowed_identity_expressions.get(path)
            if expected_identity is not None and node.value == expected_identity:
                allowed_seen.add(path)
                continue
            raise ContractError(
                "workflow may not expose a repository token, github.token, or secrets context "
                f"outside the exact reviewed GH_TOKEN env nodes, got {path} in {source}"
            )
    expected_allowed = allowed_token_paths | set(allowed_identity_expressions)
    if allowed_seen != expected_allowed:
        raise ContractError(
            "workflow must expose only the exact reviewed github token and identity expressions"
        )


def contains_repository_node(step: MappingNode, source: Path, path: str) -> bool:
    values = yaml_mapping(step, source, path)
    uses = values.get("uses")
    if uses is not None and yaml_scalar(uses, source, f"{path}.uses").startswith("./"):
        return True
    run = values.get("run")
    if run is None:
        return False
    return bool(
        re.search(
            r"(?:^|[\s;&|])(?:g?make|git|go)(?=\s|$)|(?:^|[\s;&|])(?:\./)?scripts/",
            yaml_scalar(run, source, f"{path}.run"),
        )
    )


def is_safe_gate_node(step: MappingNode, source: Path, path: str) -> bool:
    try:
        values = require_yaml_keys(step, ("name", "run"), source, path)
    except ContractError:
        return False
    commands = tuple(
        line.strip()
        for line in yaml_scalar(values["run"], source, f"{path}.run").splitlines()
        if line.strip()
    )
    return commands == SAFE_GATE_COMMANDS


def validate_workflow_semantic_safety(document: MappingNode, source: Path) -> None:
    root = yaml_mapping(document, source, "workflow")
    if "defaults" in root:
        raise ContractError(f"workflow may not override the reviewed run shell: {source}")
    on_node = root.get("on")
    if on_node is not None:
        triggers = yaml_mapping(on_node, source, "on")
        dispatch_node = triggers.get("workflow_dispatch")
        if isinstance(dispatch_node, MappingNode):
            dispatch = yaml_mapping(dispatch_node, source, "on.workflow_dispatch")
            inputs_node = dispatch.get("inputs")
            if inputs_node is not None:
                input_names = yaml_mapping_keys(
                    inputs_node, source, "on.workflow_dispatch.inputs"
                )
                if len(input_names) > REPOSITORY_WORKFLOW_DISPATCH_INPUT_LIMIT:
                    raise ContractError(
                        "workflow_dispatch inputs exceed repository-reviewed limit of "
                        f"{REPOSITORY_WORKFLOW_DISPATCH_INPUT_LIMIT}: {source}"
                    )
    top_env = root.get("env")
    if top_env is not None:
        env_values = yaml_mapping(top_env, source, "env")
        actual = {
            key: yaml_scalar(value, source, f"env.{key}") for key, value in env_values.items()
        }
        if not set(actual).issubset(SAFE_WORKFLOW_ENV) or any(
            SAFE_WORKFLOW_ENV[key] != value for key, value in actual.items()
        ):
            raise ContractError(
                f"workflow top-level env differs from the reviewed version allowlist: {source}"
            )

    jobs_node = root.get("jobs")
    if jobs_node is None:
        raise ContractError(f"workflow must define jobs: {source}")
    jobs = yaml_mapping(jobs_node, source, "jobs")
    for job_name, job_node in jobs.items():
        job_path = f"jobs.{job_name}"
        job = yaml_mapping(job_node, source, job_path)
        runner = yaml_scalar(job.get("runs-on"), source, f"{job_path}.runs-on")
        if runner != "ubuntu-24.04":
            raise ContractError(
                f"workflow job {job_name} must run on the exact Linux amd64 runner label "
                f"ubuntu-24.04: {source}"
            )
        for forbidden in ("defaults", "container", "services", "env"):
            if forbidden in job:
                raise ContractError(
                    f"workflow job {job_name} may not define {forbidden}: {source}"
                )
        steps_node = job.get("steps")
        if steps_node is None:
            raise ContractError(f"workflow job {job_name} must define steps: {source}")
        steps = yaml_sequence(steps_node, source, f"{job_path}.steps")
        checkout_indexes: list[int] = []
        for index, step_node in enumerate(steps):
            step_path = f"{job_path}.steps[{index}]"
            step = yaml_mapping(step_node, source, step_path)
            if "shell" in step:
                raise ContractError(
                    f"workflow job {job_name} may not override the reviewed step shell: {source}"
                )
            env_node = step.get("env")
            if env_node is not None:
                env_path = f"{step_path}.env"
                env_values = yaml_mapping(env_node, source, env_path)
                for env_name, env_value in env_values.items():
                    if DANGEROUS_WORKFLOW_ENV.fullmatch(env_name):
                        env_scalar = yaml_scalar(
                            env_value, source, f"{env_path}.{env_name}"
                        )
                        explicitly_cleared = (
                            env_value.tag == "tag:yaml.org,2002:str"
                            and env_scalar == ""
                        )
                        allowed_clean_value = (
                            env_path in CLEAN_EXECUTION_ENV_PATHS
                            and env_name in CLEAN_EXECUTION_ENV_MAP
                            and env_scalar == CLEAN_EXECUTION_ENV_MAP[env_name]
                        )
                        if explicitly_cleared or allowed_clean_value:
                            continue
                        raise ContractError(
                            "workflow defines dangerous execution-context environment "
                            f"{env_name}: {source}"
                        )
            uses_node = step.get("uses")
            if uses_node is None:
                continue
            uses = yaml_scalar(uses_node, source, f"{step_path}.uses")
            if re.fullmatch(r"actions/checkout@[0-9a-f]{40}", uses):
                checkout_indexes.append(index)
        if not checkout_indexes:
            if any(
                contains_repository_node(step, source, f"{job_path}.steps[{index}]")
                for index, step in enumerate(steps)
            ):
                raise ContractError(
                    f"workflow job {job_name} runs repository commands without a guarded checkout: {source}"
                )
            continue
        for checkout_index in checkout_indexes:
            checkout_path = f"{job_path}.steps[{checkout_index}]"
            checkout = yaml_mapping(steps[checkout_index], source, checkout_path)
            with_node = checkout.get("with")
            if with_node is None:
                raise ContractError(f"workflow job {job_name} checkout must define with")
            checkout_with = yaml_mapping(with_node, source, f"{checkout_path}.with")
            persist_credentials = checkout_with.get("persist-credentials")
            if not (
                isinstance(persist_credentials, ScalarNode)
                and persist_credentials.value == "false"
                and persist_credentials.tag == "tag:yaml.org,2002:bool"
            ):
                raise ContractError(
                    f"workflow job {job_name} checkout must disable persisted credentials"
                )
            require_yaml_scalar(
                checkout_with.get("filter"),
                "blob:none",
                source,
                f"{checkout_path}.with.filter",
            )
            require_yaml_scalar(
                checkout_with.get("sparse-checkout-cone-mode"),
                "false",
                source,
                f"{checkout_path}.with.sparse-checkout-cone-mode",
                tag="tag:yaml.org,2002:bool",
            )
            sparse = yaml_scalar(
                checkout_with.get("sparse-checkout"),
                source,
                f"{checkout_path}.with.sparse-checkout",
            )
            patterns = tuple(line.strip() for line in sparse.splitlines() if line.strip())
            if patterns not in reviewed_sparse_pattern_options(source):
                raise ContractError(
                    f"workflow job {job_name} sparse checkout differs from the reviewed contract"
                )
            if checkout_index + 1 >= len(steps) or not is_safe_gate_node(
                steps[checkout_index + 1],
                source,
                f"{job_path}.steps[{checkout_index + 1}]",
            ):
                raise ContractError(
                    f"workflow job {job_name} must run the exact Round6 safe-gate immediately after checkout"
                )
        first_checkout = min(checkout_indexes)
        if any(
            contains_repository_node(step, source, f"{job_path}.steps[{index}]")
            for index, step in enumerate(steps[:first_checkout])
        ):
            raise ContractError(
                f"workflow job {job_name} runs repository commands before its guarded checkout"
            )


def assert_safe_repo_path(path: Path, root: Path) -> Path:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.absolute().relative_to(root)
    except ValueError as exc:
        raise ContractError(f"gate input escapes repository root: {path}") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ContractError(f"invalid repository-relative gate input: {path}")
    relative_name = relative.as_posix()
    for part in relative.parts:
        lowered = part.lower()
        if (
            any(marker in lowered for marker in RESTRICTED_PATH_MARKERS)
            and relative_name not in REVIEWED_RESTRICTED_MARKER_SOURCE_PATHS
        ):
            raise ContractError(f"gate refuses restricted path before reading it: {relative}")
    return root / relative


def read_regular_text(path: Path, root: Path) -> str:
    safe_path = assert_safe_repo_path(path, root)
    try:
        resolved = safe_path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ContractError(f"required gate input is missing: {safe_path}") from exc
    resolved_root = root.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ContractError(f"gate input escapes repository root: {safe_path}")
    if safe_path.is_symlink() or not safe_path.is_file():
        raise ContractError(f"gate input must be a regular non-symlink file: {safe_path}")
    return safe_path.read_text(encoding="utf-8")


def read_regular_bytes(path: Path, root: Path) -> bytes:
    safe_path = assert_safe_repo_path(path, root)
    try:
        resolved = safe_path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ContractError(f"required gate input is missing: {safe_path}") from exc
    resolved_root = root.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ContractError(f"gate input escapes repository root: {safe_path}")
    if safe_path.is_symlink() or not safe_path.is_file():
        raise ContractError(f"gate input must be a regular non-symlink file: {safe_path}")
    return safe_path.read_bytes()


def logical_make_lines(text: str) -> list[str]:
    logical: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        pending = pending + line.lstrip() if pending else line
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        logical.append(pending)
        pending = ""
    if pending:
        logical.append(pending)
    return logical


def logical_shell_commands(text: str) -> tuple[str, ...]:
    commands: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        pending = f"{pending} {line}".strip() if pending else line
        trailing = len(pending) - len(pending.rstrip("\\"))
        if trailing % 2 == 1:
            pending = pending[:-1].rstrip()
            continue
        commands.append(pending)
        pending = ""
    if pending:
        raise ContractError("unterminated shell continuation in final release identity step")
    return tuple(commands)


GH_API_READ_METHODS = {"GET", "HEAD"}
GH_API_LONG_INPUT_OPTIONS = {"--field", "--raw-field", "--input"}


def shell_function_body_start(segment: list[str]) -> int | None:
    if not segment:
        return None
    if segment[0].endswith("(){"):
        return 1
    if len(segment) >= 2 and segment[0].endswith("()") and segment[1] == "{":
        return 2
    if len(segment) >= 3 and segment[1] == "()" and segment[2] == "{":
        return 3
    if segment[0] == "function" and len(segment) >= 2:
        if segment[1].endswith("(){"):
            return 2
        if len(segment) >= 3 and segment[2] == "{":
            return 3
    return None


def shell_function_uses_gh(tokens: list[str]) -> bool:
    return any(Path(token).name == "gh" for token in tokens if token not in {"{", "}"})


def gh_alias_uses_gh(args: list[str]) -> bool:
    for argument in args:
        if "=" not in argument:
            continue
        _, value = argument.split("=", 1)
        try:
            alias_segments = shell_command_segments(value)
        except (ValueError, ContractError):
            return True
        for segment in alias_segments:
            unwrapped = unwrap_shell_command(segment)
            if unwrapped is not None and Path(unwrapped[0]).name == "gh":
                return True
    return False


def gh_api_short_option(token: str) -> tuple[str, str] | None:
    if not token.startswith("-") or token.startswith("--") or token == "-":
        return None
    body = token[1:]
    while body.startswith("i"):
        body = body[1:]
    if not body:
        return None
    option = body[0]
    if option not in {"X", "f", "F", "H"}:
        return None
    value = body[1:]
    if value.startswith("="):
        value = value[1:]
    return option, value


def gh_api_arguments_mutation_reason(arguments: list[str]) -> str | None:
    methods: list[str] = []
    has_write_capable_input = False
    index = 0
    options_enabled = True
    while index < len(arguments):
        token = arguments[index]
        if options_enabled and token == "--":
            options_enabled = False
            index += 1
            continue
        if not options_enabled:
            index += 1
            continue

        if token in {"-X", "--method"}:
            if index + 1 >= len(arguments):
                return f"gh api {token} lacks a statically auditable method"
            methods.append(arguments[index + 1])
            index += 2
            continue
        if token.startswith("--method="):
            methods.append(token.split("=", 1)[1])
            index += 1
            continue

        short = gh_api_short_option(token)
        if short is not None and short[0] == "X":
            if short[1]:
                methods.append(short[1])
                index += 1
            elif index + 1 < len(arguments):
                methods.append(arguments[index + 1])
                index += 2
            else:
                return "gh api -X lacks a statically auditable method"
            continue

        if token in {"-f", "-F", *GH_API_LONG_INPUT_OPTIONS}:
            has_write_capable_input = True
            index += 2 if index + 1 < len(arguments) else 1
            continue
        if any(token.startswith(option + "=") for option in GH_API_LONG_INPUT_OPTIONS):
            has_write_capable_input = True
            index += 1
            continue
        if short is not None and short[0] in {"f", "F"}:
            has_write_capable_input = True
            index += 1 if short[1] or index + 1 >= len(arguments) else 2
            continue

        header: str | None = None
        if token in {"-H", "--header"} and index + 1 < len(arguments):
            header = arguments[index + 1]
            index += 2
        elif token.startswith("--header="):
            header = token.split("=", 1)[1]
            index += 1
        elif short is not None and short[0] == "H":
            if short[1]:
                header = short[1]
                index += 1
            elif index + 1 < len(arguments):
                header = arguments[index + 1]
                index += 2
            else:
                index += 1
        else:
            index += 1
        if header is not None and ":" in header:
            name, value = header.split(":", 1)
            if name.strip().lower() in {"x-http-method-override", "x-method-override"}:
                override = value.strip().upper()
                if override not in GH_API_READ_METHODS:
                    return f"gh api non-read method override {value.strip() or '<empty>'}"

    for method in methods:
        normalized = method.strip().upper()
        if normalized not in GH_API_READ_METHODS:
            return f"gh api non-read or dynamic method {method or '<empty>'}"
    if has_write_capable_input and not methods:
        return "gh api input parameters implicitly select POST"
    return None


def read_only_gh_api_mutation_reason(text: str) -> str | None:
    """Reject shell commands that can issue a non-read-only GitHub API request."""
    in_function = False
    for command in mutation_shell_commands(text):
        for segment in shell_command_segments(command):
            function_start = shell_function_body_start(segment)
            if function_start is not None:
                in_function = True
                if shell_function_uses_gh(segment[function_start:]):
                    return "gh shell function wrapper cannot be proven read-only"
                if "}" in segment[function_start:]:
                    in_function = False
                continue
            if in_function:
                if shell_function_uses_gh(segment):
                    return "gh shell function wrapper cannot be proven read-only"
                if "}" in segment:
                    in_function = False
                continue

            unwrapped = unwrap_shell_command(segment)
            if unwrapped is None:
                continue
            executable_path, arguments = unwrapped
            executable = Path(executable_path).name
            if executable == "alias" and gh_alias_uses_gh(arguments):
                return "gh shell alias wrapper cannot be proven read-only"
            dynamic_reason = mutating_command_reason(segment)
            if dynamic_reason is not None and any(
                marker in dynamic_reason
                for marker in ("dynamic command execution", "xargs", "find")
            ):
                return f"{dynamic_reason} cannot be proven read-only"
            if ("$" in executable_path or "`" in executable_path) and arguments[:1] == ["api"]:
                return "dynamic gh-compatible executable cannot be proven read-only"
            if executable != "gh" or arguments[:1] != ["api"]:
                continue
            reason = gh_api_arguments_mutation_reason(arguments[1:])
            if reason is not None:
                return reason
    return None


def shell_tokens(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return []
    try:
        lexer = shlex.shlex(stripped, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError as exc:
        raise ContractError(f"cannot parse gate command line: {stripped!r}: {exc}") from exc


def extract_make_targets(text: str) -> set[str]:
    targets: set[str] = set()
    for line in text.splitlines():
        if not re.search(r"(?:^|[\s;&|])(?:[^\s]*/)?g?make(?=\s|$)", line):
            continue
        tokens = shell_tokens(line)
        for index, token in enumerate(tokens):
            if Path(token).name not in {"make", "gmake"}:
                continue
            for candidate in tokens[index + 1 :]:
                if candidate in SHELL_OPERATORS:
                    break
                if candidate.startswith(("-C", "--directory", "-f", "--file", "--eval", "-E")):
                    raise ContractError(
                        f"Make directory/file/eval dispatch cannot be audited safely: {candidate!r}"
                    )
                if candidate in {"-s", "--silent", "--no-print-directory"}:
                    continue
                if candidate.startswith("-"):
                    raise ContractError(f"unsupported Make option cannot be audited safely: {candidate!r}")
                if ASSIGNMENT.match(candidate):
                    if candidate.startswith(("MAKEFILES=", "MAKEFLAGS=")):
                        raise ContractError("dynamic Make environment cannot be audited safely")
                    continue
                if "$" in candidate or "`" in candidate:
                    raise ContractError(
                        f"dynamic Make target cannot be audited safely: {candidate!r}"
                    )
                if TARGET_NAME.match(candidate):
                    targets.add(candidate)
                else:
                    raise ContractError(f"invalid Make target cannot be audited safely: {candidate!r}")
    return targets


def extract_script_references(text: str) -> set[str]:
    return {match.group(1) for match in SCRIPT_REFERENCE.finditer(text)}


def extract_static_script_variables(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    assignment = re.compile(
        r"(?m)^\s*(?:local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.+)$"
    )
    for match in assignment.finditer(text):
        references = extract_script_references(match.group(2))
        if len(references) == 1:
            result[match.group(1)] = next(iter(references))
    return result


def interpreter_script(tokens: list[str], index: int, kind: str) -> str | None:
    cursor = index + 1
    while cursor < len(tokens):
        token = tokens[cursor]
        if token in SHELL_OPERATORS:
            return None
        if token == "--":
            cursor += 1
            break
        if kind == "python" and token in {"-c", "-m"}:
            raise ContractError(f"dynamic Python dispatch is forbidden: {token}")
        if kind == "python" and token in {"-W", "-X"}:
            cursor += 2
            continue
        if token.startswith("-") and token != "-":
            cursor += 1
            continue
        break
    if cursor >= len(tokens) or tokens[cursor] in SHELL_OPERATORS:
        return None
    candidate = tokens[cursor]
    if candidate == "-" and kind == "python":
        return None
    references = extract_script_references(candidate)
    if "$" in candidate or "`" in candidate:
        if len(references) != 1:
            raise ContractError(
                f"dynamic {kind} script path cannot be audited safely: {candidate!r}"
            )
        return next(iter(references))
    expected_suffix = ".py" if kind == "python" else ".sh"
    if not candidate.endswith(expected_suffix):
        raise ContractError(
            f"{kind} invocation must use a static repository {expected_suffix} script: {candidate!r}"
        )
    return candidate.removeprefix("./")


def command_indexes(tokens: list[str]) -> set[int]:
    indexes: set[int] = set()
    start = 0
    while start < len(tokens):
        end = start
        while end < len(tokens) and tokens[end] not in SHELL_OPERATORS:
            end += 1
        cursor = start
        while cursor < end and (
            ASSIGNMENT.match(tokens[cursor])
            or tokens[cursor] in {"if", "then", "while", "until", "do", "!", "time"}
        ):
            cursor += 1
        if cursor < end and tokens[cursor] in {"env", "sudo"}:
            cursor += 1
            while cursor < end and (
                ASSIGNMENT.match(tokens[cursor]) or tokens[cursor].startswith("-")
            ):
                cursor += 1
        if cursor < end:
            indexes.add(cursor)
        start = end + 1
    return indexes


SHELL_NEUTRAL_STATE = (("normal", 0),)


def shell_state_neutral(state: tuple[tuple[str, int], ...]) -> bool:
    return state == SHELL_NEUTRAL_STATE


def scan_shell_command_fragment(
    text: str, state: tuple[tuple[str, int], ...]
) -> tuple[str, tuple[tuple[str, int], ...]]:
    contexts = [[mode, depth] for mode, depth in state]
    index = 0
    code_end = len(text)
    while index < len(text):
        mode, depth = contexts[-1]
        character = text[index]
        if mode == "single":
            if character == "'":
                contexts[-1][0] = "normal"
            index += 1
            continue
        if mode == "backtick":
            if character == "\\":
                index += 2 if index + 1 < len(text) else 1
                continue
            if character == "`":
                contexts.pop()
                index += 1
                continue
            if character == "$" and text[index + 1 : index + 2] == "(":
                contexts.append(["normal", 1])
                index += 2
                continue
            index += 1
            continue
        if character == "\\":
            index += 2 if index + 1 < len(text) else 1
            continue
        if character == "$" and text[index + 1 : index + 2] == "(":
            contexts.append(["normal", 1])
            index += 2
            continue
        if mode == "double":
            if character == '"':
                contexts[-1][0] = "normal"
            elif character == "`":
                contexts.append(["backtick", -1])
            index += 1
            continue
        if character == "'":
            contexts[-1][0] = "single"
            index += 1
            continue
        if character == '"':
            contexts[-1][0] = "double"
            index += 1
            continue
        if character == "`":
            contexts.append(["backtick", -1])
            index += 1
            continue
        if (
            character == "#"
            and (index == 0 or text[index - 1].isspace() or text[index - 1] in ";|&(")
        ):
            code_end = index
            break
        if character in "<>" and text[index + 1 : index + 2] == "(":
            contexts.append(["normal", 1])
            index += 2
            continue
        if depth > 0 and character == "(":
            contexts[-1][1] += 1
        elif depth > 0 and character == ")":
            contexts[-1][1] -= 1
            if contexts[-1][1] == 0:
                contexts.pop()
        index += 1
    return text[:code_end].rstrip(), tuple((mode, depth) for mode, depth in contexts)


def shell_line_continuation(
    text: str, state: tuple[tuple[str, int], ...]
) -> tuple[str, tuple[tuple[str, int], ...], bool]:
    code, next_state = scan_shell_command_fragment(text, state)
    trailing = len(code) - len(code.rstrip("\\"))
    in_single = next_state[-1][0] == "single"
    return code, next_state, trailing % 2 == 1 and not in_single


def scan_shell_array_fragment(
    text: str, source: Path, state: tuple[bool, bool]
) -> tuple[bool, bool]:
    in_single, in_double = state
    index = 0
    while index < len(text):
        character = text[index]
        if in_single:
            if character == "'":
                in_single = False
            index += 1
            continue
        if character == "\\":
            index += 2 if index + 1 < len(text) else 1
            continue
        if character == "'" and not in_double:
            in_single = True
            index += 1
            continue
        if character == '"':
            in_double = not in_double
            index += 1
            continue
        if (
            character == "#"
            and not in_double
            and (index == 0 or text[index - 1].isspace() or text[index - 1] in ";|&(")
        ):
            break
        if character == "`" or (
            character == "$"
            and text[index + 1 : index + 2] == "("
            and text[index + 1 : index + 3] != "(("
        ) or (
            not in_double
            and character in "<>"
            and text[index + 1 : index + 2] == "("
        ):
            raise ContractError(
                f"shell array contains executable substitution that cannot be audited safely: {source}"
            )
        index += 1
    return in_single, in_double


def auditable_shell_commands(text: str, source: Path) -> tuple[str, ...]:
    commands: list[str] = []
    pending = ""
    heredocs: list[tuple[str, bool]] = []
    in_array = False
    array_state = (False, False)
    command_state = SHELL_NEUTRAL_STATE
    array_start = re.compile(
        r"^(?:(?:local|readonly|declare)(?:\s+-[aA])?\s+)?"
        r"[A-Za-z_][A-Za-z0-9_]*\+?=\("
    )
    for raw in text.splitlines():
        if heredocs:
            delimiter, strip_tabs = heredocs[0]
            candidate = raw.lstrip("\t") if strip_tabs else raw
            if candidate == delimiter:
                heredocs.pop(0)
                if not heredocs and shell_state_neutral(command_state) and pending:
                    commands.append(pending)
                    pending = ""
            continue

        line = raw.strip()
        if not line or (line.startswith("#") and shell_state_neutral(command_state)):
            continue
        if in_array:
            array_state = scan_shell_array_fragment(line, source, array_state)
            if array_state == (False, False) and re.fullmatch(
                r"\)\s*;?(?:\s+#.*)?", line
            ):
                in_array = False
            continue
        if shell_state_neutral(command_state) and not pending and array_start.match(line):
            array_state = scan_shell_array_fragment(line, source, (False, False))
            if array_state != (False, False) or not re.search(
                r"\)\s*;?(?:\s+#.*)?$", line
            ):
                in_array = True
            continue

        line, command_state, continued = shell_line_continuation(line, command_state)
        if not line:
            continue
        if continued:
            line = line[:-1].rstrip()
        pending = f"{pending} {line}".strip() if pending else line
        for match in HEREDOC.finditer(line):
            delimiter = match.group("delimiter")
            if delimiter[:1] in {"'", '"'}:
                delimiter = delimiter[1:-1]
            heredocs.append((delimiter, match.group("strip_tabs") == "-"))
        if continued or heredocs or not shell_state_neutral(command_state):
            continue
        commands.append(pending)
        pending = ""

    if pending or heredocs or in_array or not shell_state_neutral(command_state):
        raise ContractError(f"unterminated shell construct cannot be audited safely: {source}")
    return tuple(commands)


def reject_dynamic_dispatch(text: str, source: Path) -> set[str]:
    if re.search(r"(?m)(?:^|[;&|])\s*(?:env\s+[^\n;&|]*\s+)?(?:bash|sh)\s+[^\n;&|]*-c(?:\s|$)", text):
        raise ContractError(f"dynamic shell dispatch cannot be audited safely: {source}")
    if re.search(r"(?m)(?:^|[;&|])\s*(?:env\s+[^\n;&|]*\s+)?python(?:3(?:\.\d+)?)?\s+[^\n;&|]*(?:-c|-m)(?:\s|$)", text):
        raise ContractError(f"dynamic Python dispatch cannot be audited safely: {source}")
    if re.search(r"(?m)(?:^|[;&|])\s*eval(?:\s|$)|\$\((?:MAKE|\{?MAKE\}?)\)", text):
        raise ContractError(f"dynamic shell/Make dispatch cannot be audited safely: {source}")
    if re.search(r"(?m)\bMAKEFILES\s*=|\bMAKEFLAGS\s*=|\bxargs\b|\bfind\b[^\n]*-exec\b", text):
        raise ContractError(f"dynamic command fan-out cannot be audited safely: {source}")

    scripts = set(extract_script_references(text))
    static_variables = extract_static_script_variables(text)
    variable_command = re.compile(
        r"^\s*(?:(?:if|while|until|then)\s+|!\s+)?[\"']?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"
    )
    for line in auditable_shell_commands(text, source):
        match = variable_command.search(line)
        if match and not extract_script_references(line):
            variable = match.group(1)
            if variable in static_variables:
                scripts.add(static_variables[variable])
            elif variable not in SAFE_DYNAMIC_TOOL_VARIABLES:
                raise ContractError(
                    f"dynamic command variable cannot be audited safely in {source}: ${variable}"
                )

        if not re.search(
            r"(?:^|\s)(?:python(?:3(?:\.\d+)?)?|bash|sh|source|\.)(?:\s|$)",
            line,
        ) and not re.search(r"(?:^|[\s;&|])\.\.?/", line):
            continue
        tokens = shell_tokens(line)
        for index in command_indexes(tokens):
            token = tokens[index]
            name = Path(token).name
            if token.startswith(("./", "../")):
                references = extract_script_references(token)
                normalized = token.removeprefix("./")
                if len(references) != 1 or normalized not in references:
                    raise ContractError(
                        f"direct repository executable cannot be audited safely in {source}: {token!r}"
                    )
                scripts.update(references)
            if re.fullmatch(r"python(?:3(?:\.\d+)?)?", name):
                script = interpreter_script(tokens, index, "python")
                if script:
                    scripts.add(script)
            elif name in {"bash", "sh"}:
                script = interpreter_script(tokens, index, "shell")
                if script:
                    scripts.add(script)
            elif token in {"source", "."}:
                script = interpreter_script(tokens, index, "shell")
                if script:
                    scripts.add(script)
    return scripts


def reject_go_all_packages(text: str, source: Path) -> None:
    for line in text.splitlines():
        if "./..." not in line:
            continue
        tokens = shell_tokens(line)
        for index, token in enumerate(tokens):
            normalized = token.strip('"\'')
            is_go = (
                Path(normalized).name == "go"
                or normalized in {"$(GO)", "$GO", "${GO}", "$go_bin", "${go_bin}"}
            )
            if not is_go:
                continue
            for candidate in tokens[index + 1 :]:
                if candidate in SHELL_OPERATORS:
                    break
                if candidate == "./...":
                    raise ContractError(f"reachable go ... ./... is forbidden: {source}")


def audit_command_text(text: str, source: Path) -> tuple[set[str], set[str]]:
    scripts = reject_dynamic_dispatch(text, source)
    reject_go_all_packages(text, source)
    return extract_make_targets(text), scripts | extract_script_references(text)


def mapping_block(text: str, key: str, indent: int) -> str:
    lines = text.splitlines()
    prefix = " " * indent
    start = None
    for index, line in enumerate(lines):
        if line == f"{prefix}{key}:" or line.startswith(f"{prefix}{key}: "):
            start = index
            break
    if start is None:
        raise ContractError(f"required YAML key is missing: {key}")
    collected = [lines[start]]
    for line in lines[start + 1 :]:
        if not line.strip():
            collected.append(line)
            continue
        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent <= indent:
            break
        collected.append(line)
    return "\n".join(collected)


def yaml_run_blocks(text: str) -> list[str]:
    lines = text.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)(-\s+)?run:\s*(.*)$", lines[index])
        if not match:
            index += 1
            continue
        indent = len(match.group(1)) + (len(match.group(2)) if match.group(2) else 0)
        value = match.group(3).strip()
        if value and not value.startswith(("|", ">")):
            blocks.append(value)
            index += 1
            continue
        collected: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip():
                current_indent = len(line) - len(line.lstrip(" "))
                if current_indent <= indent:
                    break
                collected.append(line[indent + 2 :])
            else:
                collected.append("")
            index += 1
        blocks.append("\n".join(collected))
    return blocks


def job_blocks(text: str) -> dict[str, str]:
    jobs = mapping_block(text, "jobs", 0)
    lines = jobs.splitlines()
    starts: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            starts.append((index, match.group(1)))
    result: dict[str, str] = {}
    for position, (start, name) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        result[name] = "\n".join(lines[start:end])
    if not result:
        raise ContractError("workflow must define at least one job")
    return result


def step_blocks(job: str) -> list[str]:
    lines = job.splitlines()
    starts = [index for index, line in enumerate(lines) if re.match(r"^      -\s+", line)]
    result: list[str] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        result.append("\n".join(lines[start:end]))
    return result


def sparse_patterns_from_checkout(step: str) -> tuple[str, ...]:
    match = re.search(r"(?m)^(\s*)sparse-checkout:\s*\|\s*$", step)
    if not match:
        raise ContractError("Round6 checkout must define sparse-checkout as a literal block")
    lines = step.splitlines()
    start = step[: match.start()].count("\n")
    indent = len(match.group(1))
    patterns: list[str] = []
    for line in lines[start + 1 :]:
        if not line.strip():
            continue
        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent <= indent:
            break
        patterns.append(line.strip())
    return tuple(patterns)


def is_safe_gate_step(step: str) -> bool:
    if re.search(r"(?m)^\s+continue-on-error:\s*true\s*$", step):
        return False
    if re.search(r"(?m)^\s+if:\s*", step):
        return False
    runs = yaml_run_blocks(step)
    if len(runs) != 1:
        return False
    commands = tuple(line.strip() for line in runs[0].splitlines() if line.strip())
    return commands == SAFE_GATE_COMMANDS


def is_round9_safe_gate_step(step: str) -> bool:
    if re.search(r"(?m)^\s+if:\s*", step):
        return False
    runs = yaml_run_blocks(step)
    if len(runs) != 1:
        return False
    commands = tuple(line.strip() for line in runs[0].splitlines() if line.strip())
    return commands == ROUND9_SAFE_GATE_COMMANDS


def is_round9_safe_gate_bootstrap_step(step: str) -> bool:
    if re.search(r"(?m)^\s+continue-on-error:\s*true\s*$", step):
        return False
    if re.search(r"(?m)^\s+if:\s*", step):
        return False
    if not re.search(
        r"(?m)^\s+-\s+name:\s*Install exact Safe Gate runtime before checkout\s*$",
        step,
    ):
        return False
    runs = yaml_run_blocks(step)
    if len(runs) != 1:
        return False
    commands = tuple(line.strip() for line in runs[0].splitlines() if line.strip())
    return commands == ROUND9_SAFE_GATE_BOOTSTRAP_COMMANDS


def contains_repository_command(step: str) -> bool:
    if re.search(r"(?m)^\s+(?:-\s+)?uses:\s*\./", step):
        return True
    for command in yaml_run_blocks(step):
        if re.search(
            r"(?:^|[\s;&|])(?:g?make|git|go)(?=\s|$)|(?:^|[\s;&|])(?:\./)?scripts/",
            command,
        ):
            return True
    return False


def reject_workflow_yaml_indirection(text: str, source: Path) -> None:
    block_scalar_indent: int | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if block_scalar_indent is not None:
            if indent > block_scalar_indent:
                continue
            block_scalar_indent = None
        stripped = raw_line.lstrip(" ")
        if stripped.startswith(("%", "---", "...", "? ")):
            raise ContractError(f"workflow uses unsupported YAML directives/keys: {source}")
        if stripped.startswith(("&", "*", "!")):
            raise ContractError(
                f"workflow may not use YAML anchors, aliases, merges, or tags: {source}"
            )
        if re.match(r'^(?:"[^"]*"|\'[^\']*\')\s*:', stripped):
            raise ContractError(f"workflow mapping keys may not be quoted: {source}")
        if re.match(r"^<<\s*:", stripped) or re.search(
            r"(?::\s*|-\s+)(?:[&*][A-Za-z_][A-Za-z0-9_-]*|!![^\s#]+)",
            stripped,
        ):
            raise ContractError(f"workflow may not use YAML anchors, aliases, merges, or tags: {source}")
        if re.search(r":\s*[\[{]", stripped):
            raise ContractError(f"workflow may not use flow-style YAML mappings/sequences: {source}")
        if re.match(r"^[A-Za-z0-9_-]+\s*:\s*[|>][+-]?\s*(?:#.*)?$", stripped):
            block_scalar_indent = indent


def validate_workflow_environment(text: str, source: Path) -> None:
    top_env_count = len(re.findall(r"(?m)^env:\s*(?:$|#)", text))
    if top_env_count > 1:
        raise ContractError(f"workflow may define top-level env at most once: {source}")
    if top_env_count == 1:
        env_block = mapping_block(text, "env", 0)
        env_lines = {
            line.strip() for line in env_block.splitlines()[1:] if line.strip()
        }
        if not env_lines.issubset(SAFE_WORKFLOW_ENV_LINES):
            raise ContractError(f"workflow top-level env differs from the reviewed version allowlist: {source}")
    if re.search(r"(?m)^    env:\s*(?:$|#)", text):
        raise ContractError(f"workflow jobs may not inherit custom job-level env: {source}")


def validate_workflow_safety(text: str, source: Path) -> tuple[tuple[str, ...], ...]:
    document = parse_workflow_yaml(text, source)
    validate_workflow_semantic_safety(document, source)
    reject_workflow_yaml_indirection(text, source)
    validate_workflow_environment(text, source)
    if re.search(r"(?m)^defaults:\s*(?:$|#)", text):
        raise ContractError(f"workflow may not override the reviewed run shell: {source}")
    sparse_sets: list[tuple[str, ...]] = []
    for job_name, job in job_blocks(text).items():
        runners = re.findall(r"(?m)^    runs-on:\s*([^\s#]+)\s*(?:#.*)?$", job)
        if runners != ["ubuntu-24.04"]:
            raise ContractError(
                f"workflow job {job_name} must run on the exact Linux amd64 runner label ubuntu-24.04: {source}"
            )
        for key in ("defaults", "container", "services"):
            if re.search(rf"(?m)^    {key}:\s*", job):
                raise ContractError(
                    f"workflow job {job_name} may not define {key}: {source}"
                )
        steps = step_blocks(job)
        if any(re.search(r"(?m)^        shell:\s*", step) for step in steps):
            raise ContractError(
                f"workflow job {job_name} may not override the reviewed step shell: {source}"
            )
        checkout_indexes = [
            index
            for index, step in enumerate(steps)
            if re.search(
                r"(?m)^\s+(?:-\s+)?uses:\s*actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$",
                step,
            )
        ]
        if not checkout_indexes:
            if any(contains_repository_command(step) for step in steps):
                raise ContractError(
                    f"workflow job {job_name} runs repository commands without a guarded checkout: {source}"
                )
            continue
        for checkout_index in checkout_indexes:
            checkout = steps[checkout_index]
            if not re.search(r"(?m)^\s+persist-credentials:\s*false\s*$", checkout):
                raise ContractError(
                    f"workflow job {job_name} checkout must disable persisted credentials"
                )
            if not re.search(r"(?m)^\s+filter:\s*blob:none\s*$", checkout):
                raise ContractError(f"workflow job {job_name} checkout must use filter: blob:none")
            if not re.search(r"(?m)^\s+sparse-checkout-cone-mode:\s*false\s*$", checkout):
                raise ContractError(
                    f"workflow job {job_name} checkout must use sparse-checkout-cone-mode: false"
                )
            patterns = sparse_patterns_from_checkout(checkout)
            if patterns not in reviewed_sparse_pattern_options(source):
                raise ContractError(
                    f"workflow job {job_name} sparse checkout differs from the reviewed contract"
                )
            sparse_sets.append(patterns)
            if checkout_index + 1 >= len(steps) or not is_safe_gate_step(
                steps[checkout_index + 1]
            ):
                raise ContractError(
                    f"workflow job {job_name} must run the exact Round6 safe-gate immediately after checkout"
                )
        first_checkout = min(checkout_indexes)
        if any(contains_repository_command(step) for step in steps[:first_checkout]):
            raise ContractError(
                f"workflow job {job_name} runs repository commands before its guarded checkout"
            )
    return tuple(sparse_sets)


def exact_string_mapping(
    node: Node, source: Path, path: str
) -> tuple[tuple[str, str], ...]:
    if not isinstance(node, MappingNode):
        raise ContractError(f"workflow {path} must be a mapping")
    values: list[tuple[str, str]] = []
    for key_node, value_node in node.value:
        if value_node.tag != "tag:yaml.org,2002:str":
            raise ContractError(f"workflow {path}.{key_node.value} must be an exact string")
        values.append(
            (
                key_node.value,
                yaml_scalar(value_node, source, f"{path}.{key_node.value}"),
            )
        )
    return tuple(values)


def validate_codeql_workflow(text: str, source: Path) -> None:
    validate_workflow_safety(text, source)
    required_manual_build_lines = (
        "uses: actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16 # v6.5.0",
        "go-version: ${{ env.GO_VERSION }}",
        "build-mode: manual",
        "run: go build -mod=readonly -tags=sqlite_omit_load_extension "
        "./cmd/cyber-abuse-guard ./internal/... ./rules",
    )
    if any(text.count(line) != 1 for line in required_manual_build_lines):
        raise ContractError(
            "CodeQL workflow differs from the exact reviewed setup-go pin, "
            "manual build mode, or Go build command"
        )
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != CODEQL_WORKFLOW_SHA256:
        raise ContractError(
            "CodeQL workflow differs from the exact reviewed trigger, permission, action, and build contract"
        )


def validate_candidate_workflow(text: str, source: Path) -> None:
    validate_workflow_safety(text, source)
    document = parse_workflow_yaml(text, source)
    validate_sensitive_workflow_expressions(
        document,
        source,
        allowed_token_paths=CANDIDATE_ALLOWED_GITHUB_TOKEN_PATHS,
        allowed_identity_expressions=CANDIDATE_ALLOWED_GITHUB_IDENTITY_EXPRESSIONS,
    )
    root = require_yaml_keys(document, CANDIDATE_TOP_LEVEL_KEYS, source, "workflow")
    require_yaml_scalar(root["name"], CANDIDATE_WORKFLOW_NAME, source, "name")

    if yaml_mapping_keys(root["on"], source, "on") != ("workflow_dispatch",):
        raise ContractError("Round6 candidate must remain manual-only workflow_dispatch")
    on = yaml_mapping(root["on"], source, "on")
    dispatch = require_yaml_keys(
        on["workflow_dispatch"], ("inputs",), source, "on.workflow_dispatch"
    )
    inputs = require_yaml_keys(
        dispatch["inputs"],
        CANDIDATE_INPUT_ORDER,
        source,
        "on.workflow_dispatch.inputs",
    )
    for input_name, input_node in inputs.items():
        path = f"on.workflow_dispatch.inputs.{input_name}"
        expected_keys = (
            ("description", "required", "type", "default")
            if input_name == "authorize_clean_candidate"
            else ("description", "required", "type")
        )
        values = require_yaml_keys(input_node, expected_keys, source, path)
        if not yaml_scalar(values["description"], source, f"{path}.description").strip():
            raise ContractError(f"workflow {path}.description may not be empty")
        require_yaml_scalar(
            values["required"],
            "true",
            source,
            f"{path}.required",
            tag="tag:yaml.org,2002:bool",
        )
        if input_name == "authorize_clean_candidate":
            require_yaml_scalar(values["type"], "boolean", source, f"{path}.type")
            require_yaml_scalar(
                values["default"],
                "false",
                source,
                f"{path}.default",
                tag="tag:yaml.org,2002:bool",
            )
        else:
            require_yaml_scalar(values["type"], "string", source, f"{path}.type")

    permissions = require_yaml_keys(
        root["permissions"], ("actions", "contents"), source, "permissions"
    )
    require_yaml_scalar(permissions["actions"], "read", source, "permissions.actions")
    require_yaml_scalar(permissions["contents"], "read", source, "permissions.contents")
    concurrency = require_yaml_keys(
        root["concurrency"], ("group", "cancel-in-progress"), source, "concurrency"
    )
    require_yaml_scalar(
        concurrency["group"],
        "round6-clean-candidate-${{ inputs.expected_commit }}",
        source,
        "concurrency.group",
    )
    require_yaml_scalar(
        concurrency["cancel-in-progress"],
        "false",
        source,
        "concurrency.cancel-in-progress",
        tag="tag:yaml.org,2002:bool",
    )
    env = require_yaml_keys(
        root["env"],
        ("GO_VERSION", "VERSION", "CYCLONEDX_GOMOD_VERSION", "GOVULNCHECK_VERSION"),
        source,
        "env",
    )
    for env_name in (
        "GO_VERSION",
        "VERSION",
        "CYCLONEDX_GOMOD_VERSION",
        "GOVULNCHECK_VERSION",
    ):
        require_yaml_scalar(
            env[env_name], SAFE_WORKFLOW_ENV[env_name], source, f"env.{env_name}"
        )

    jobs = require_yaml_keys(root["jobs"], ("admission", "build"), source, "jobs")
    steps_by_job: dict[str, list[Node]] = {}
    for job_name in ("admission", "build"):
        job_path = f"jobs.{job_name}"
        job = require_yaml_keys(
            jobs[job_name], CANDIDATE_JOB_KEYS[job_name], source, job_path
        )
        require_yaml_scalar(job["runs-on"], "ubuntu-24.04", source, f"{job_path}.runs-on")
        require_yaml_scalar(
            job["timeout-minutes"],
            "5" if job_name == "admission" else "45",
            source,
            f"{job_path}.timeout-minutes",
            tag="tag:yaml.org,2002:int",
        )
        if job_name == "build":
            require_yaml_scalar(job["needs"], "admission", source, f"{job_path}.needs")
            job_permissions = require_yaml_keys(
                job["permissions"], ("contents",), source, f"{job_path}.permissions"
            )
            require_yaml_scalar(
                job_permissions["contents"],
                "read",
                source,
                f"{job_path}.permissions.contents",
            )

        steps = yaml_sequence(job["steps"], source, f"{job_path}.steps")
        contracts = CANDIDATE_STEP_CONTRACTS[job_name]
        if len(steps) != len(contracts):
            raise ContractError(
                f"Round6 candidate {job_name} job must contain exactly "
                f"{len(contracts)} reviewed steps"
            )
        for index, (step_node, contract) in enumerate(zip(steps, contracts)):
            expected_name, expected_keys, expected_action = contract
            step_path = f"{job_path}.steps[{index}]"
            step = require_yaml_keys(step_node, expected_keys, source, step_path)
            require_yaml_scalar(step["name"], expected_name, source, f"{step_path}.name")
            if expected_action is not None:
                require_yaml_scalar(step["uses"], expected_action, source, f"{step_path}.uses")
            contract_key = (job_name, index)
            if "run" in step:
                run_node = step["run"]
                run_text = yaml_scalar(run_node, source, f"{step_path}.run")
                expected_hash = CANDIDATE_STEP_RUN_SHA256.get(contract_key)
                if (
                    expected_hash is None
                    or run_node.tag != "tag:yaml.org,2002:str"
                    or run_node.style != CANDIDATE_STEP_RUN_STYLE[contract_key]
                    or hashlib.sha256(run_text.encode("utf-8")).hexdigest()
                    != expected_hash
                ):
                    raise ContractError(
                        f"Round6 candidate {step_path} run must match the exact reviewed text"
                    )
                for command in mutation_shell_commands(run_text):
                    for segment in shell_command_segments(command):
                        reason = mutating_command_reason(segment)
                        if reason is not None:
                            raise ContractError(
                                f"Round6 candidate forbids {reason}: {step_path}"
                            )
            elif contract_key in CANDIDATE_STEP_RUN_SHA256:
                raise ContractError(f"Round6 candidate {step_path} is missing reviewed run")
            if "env" in step:
                actual_env = exact_string_mapping(step["env"], source, f"{step_path}.env")
                if actual_env != CANDIDATE_STEP_ENV.get(contract_key):
                    raise ContractError(
                        f"Round6 candidate {step_path}.env must match the exact reviewed mapping"
                    )
            elif contract_key in CANDIDATE_STEP_ENV:
                raise ContractError(f"Round6 candidate {step_path} is missing reviewed env")
            if "with" in step:
                yaml_mapping(step["with"], source, f"{step_path}.with")
        steps_by_job[job_name] = steps

    checkout = yaml_mapping(steps_by_job["build"][0], source, "jobs.build.steps[0]")
    checkout_with = require_yaml_keys(
        checkout["with"],
        (
            "ref",
            "fetch-depth",
            "persist-credentials",
            "filter",
            "sparse-checkout-cone-mode",
            "sparse-checkout",
        ),
        source,
        "jobs.build.steps[0].with",
    )
    require_yaml_scalar(
        checkout_with["ref"],
        "${{ inputs.expected_commit }}",
        source,
        "jobs.build.steps[0].with.ref",
    )
    require_yaml_scalar(
        checkout_with["fetch-depth"],
        "0",
        source,
        "jobs.build.steps[0].with.fetch-depth",
        tag="tag:yaml.org,2002:int",
    )
    require_yaml_scalar(
        checkout_with["persist-credentials"],
        "false",
        source,
        "jobs.build.steps[0].with.persist-credentials",
        tag="tag:yaml.org,2002:bool",
    )
    require_yaml_scalar(
        checkout_with["filter"], "blob:none", source, "jobs.build.steps[0].with.filter"
    )
    require_yaml_scalar(
        checkout_with["sparse-checkout-cone-mode"],
        "false",
        source,
        "jobs.build.steps[0].with.sparse-checkout-cone-mode",
        tag="tag:yaml.org,2002:bool",
    )
    sparse = yaml_scalar(
        checkout_with["sparse-checkout"], source, "jobs.build.steps[0].with.sparse-checkout"
    )
    if tuple(line.strip() for line in sparse.splitlines() if line.strip()) != ROUND6_SPARSE_PATTERNS:
        raise ContractError("Round6 candidate checkout sparse boundary changed")

    setup_go = yaml_mapping(steps_by_job["build"][3], source, "jobs.build.steps[3]")
    setup_go_with = require_yaml_keys(
        setup_go["with"], ("go-version", "cache"), source, "jobs.build.steps[3].with"
    )
    require_yaml_scalar(
        setup_go_with["go-version"],
        "${{ env.GO_VERSION }}",
        source,
        "jobs.build.steps[3].with.go-version",
    )
    require_yaml_scalar(
        setup_go_with["cache"],
        "true",
        source,
        "jobs.build.steps[3].with.cache",
        tag="tag:yaml.org,2002:bool",
    )

    upload = yaml_mapping(steps_by_job["build"][9], source, "jobs.build.steps[9]")
    upload_with = require_yaml_keys(
        upload["with"],
        ("name", "path", "if-no-files-found", "retention-days"),
        source,
        "jobs.build.steps[9].with",
    )
    require_yaml_scalar(
        upload_with["name"],
        "round6-v0.15-candidate-${{ inputs.expected_commit }}",
        source,
        "jobs.build.steps[9].with.name",
    )
    upload_paths = yaml_scalar(upload_with["path"], source, "jobs.build.steps[9].with.path")
    if tuple(line.strip() for line in upload_paths.splitlines() if line.strip()) != CANDIDATE_ARTIFACTS:
        raise ContractError("Round6 candidate private artifact allowlist changed")
    require_yaml_scalar(
        upload_with["if-no-files-found"],
        "error",
        source,
        "jobs.build.steps[9].with.if-no-files-found",
    )
    require_yaml_scalar(
        upload_with["retention-days"],
        "30",
        source,
        "jobs.build.steps[9].with.retention-days",
        tag="tag:yaml.org,2002:int",
    )

    if re.search(r"(?m)^\s*contents\s*:\s*write\s*$", text):
        raise ContractError("Round6 candidate workflow must remain contents: read only")
    if re.search(
        r"(?i)(?:softprops/action-gh-release|\bgh\s+release\b|\bgit\s+(?:tag|push|update-ref)\b)",
        text,
    ):
        raise ContractError("Round6 candidate workflow may not create tags or releases")


def validate_candidate_script(text: str, source: Path) -> None:
    expected_hash = CANDIDATE_SCRIPT_SHA256.get(source.name)
    if expected_hash is None:
        raise ContractError(f"unreviewed Round6 candidate script: {source}")
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != expected_hash:
        raise ContractError(
            f"Round6 candidate script must match the exact reviewed safety contract: {source}"
        )


def validate_reproducibility_wrapper_script(text: str, source: Path) -> None:
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != REPRODUCIBILITY_WRAPPER_SCRIPT_SHA256
    ):
        raise ContractError(
            f"legacy reproducibility wrapper must match the exact reviewed safety contract: {source}"
        )


def validate_frozen_evaluation_tree_script(text: str, source: Path) -> None:
    if text.count(FROZEN_EVALUATION_STATUS_COMMAND) != 1:
        raise ContractError(
            "frozen evaluation tree verifier must reject staged, unstaged, and untracked paths: "
            f"{source}"
        )
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != FROZEN_EVALUATION_TREE_SCRIPT_SHA256
    ):
        raise ContractError(
            f"frozen evaluation tree verifier must match the exact reviewed metadata-only contract: {source}"
        )


def validate_round6_doc_fixture_wrapper_script(
    text: str, source: Path, root: Path
) -> None:
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != ROUND6_DOC_FIXTURE_WRAPPER_SCRIPT_SHA256
    ):
        raise ContractError(
            f"Round6 document fixture wrapper must match the exact reviewed contract: {source}"
        )
    wrapper_pin_names = {
        "scripts/release-doc-consistency-test.sh": "expected_fixture_sha256",
        "scripts/release-doc-consistency.sh": "expected_gate_sha256",
    }
    for relative, expected in ROUND6_DOC_FIXTURE_DEPENDENCY_SHA256.items():
        pin_line = f"{wrapper_pin_names[relative]}='{expected}'"
        if text.count(pin_line) != 1:
            raise ContractError(
                f"Round6 document fixture wrapper must pin the reviewed dependency hash: {relative}"
            )
        dependency = root / relative
        dependency_text = read_regular_text(dependency, root)
        if hashlib.sha256(dependency_text.encode("utf-8")).hexdigest() != expected:
            raise ContractError(
                f"Round6 document fixture dependency changed outside the reviewed contract: {dependency}"
            )


def validate_round6_privacy_fixture_script(text: str, source: Path) -> None:
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != ROUND6_PRIVACY_FIXTURE_SCRIPT_SHA256
    ):
        raise ContractError(
            f"Round6 privacy fixture must match the exact reviewed contract: {source}"
        )


def validate_cpa_module_pins(root: Path) -> None:
    identities = {
        "primary": (
            CPA_CURRENT_VERSION,
            CPA_CURRENT_MODULE_SUM,
            CPA_CURRENT_GO_MOD_SUM,
        ),
    }
    for mod_relative, sum_relative, profile in CPA_PINNED_MODULE_FILES:
        version, module_sum, go_mod_sum = identities[profile]
        expected_requirement = f"{CPA_MODULE_PATH} {version}"
        mod_path = root / mod_relative
        sum_path = root / sum_relative
        mod_text = read_regular_text(mod_path, root)
        requirements: list[str] = []
        for line in mod_text.splitlines():
            candidate = line.strip()
            if candidate.startswith("require "):
                candidate = candidate.removeprefix("require ").strip()
            if candidate.startswith(f"{CPA_MODULE_PATH} "):
                requirements.append(candidate)
        if tuple(requirements) != (expected_requirement,) or re.search(
            rf"(?m)^\s*(?:replace|exclude)\s+{re.escape(CPA_MODULE_PATH)}(?:\s|$)",
            mod_text,
        ):
            raise ContractError(
                f"checked-in CPA module pin must remain exactly {expected_requirement}: {mod_relative}"
            )
        expected_sums = (
            f"{expected_requirement} {module_sum}",
            f"{expected_requirement}/go.mod {go_mod_sum}",
        )
        sum_text = read_regular_text(sum_path, root)
        actual_sums = tuple(
            line.strip()
            for line in sum_text.splitlines()
            if line.startswith(f"{CPA_MODULE_PATH} ")
        )
        if actual_sums != expected_sums:
            raise ContractError(
                f"checked-in CPA sums must remain pinned to the reviewed {profile} contract: {sum_relative}"
            )


def validate_cpa_compat_script(text: str, source: Path) -> None:
    if any(
        forbidden in text
        for forbidden in (
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "${{ github.token }}",
            "Authorization:",
            "releases/tags",
        )
    ):
        raise ContractError(
            f"CPA source verification must not use a repository token or authenticated release metadata: {source}"
        )
    latest_api_assignment = f"cpa_latest_release_api='{CPA_LATEST_RELEASE_API}'"
    if text.count(latest_api_assignment) != 1 or text.count("api.github.com") != 1:
        raise ContractError(
            f"CPA primary verification must query exactly the official latest Release endpoint: {source}"
        )
    for required in (
        'go_launcher="${GO:-go}"',
        'selected_go_root="$("$go_launcher" -C "$root" env GOROOT)"',
        'go_bin="$selected_go_root/bin/go"',
        "export GOTOOLCHAIN=go1.26.4",
        "export GOTOOLCHAIN=local",
        "export GOFLAGS=-mod=readonly",
        'selected_go_version="$("$go_bin" env GOVERSION)"',
        '[[ "$selected_go_version" == go1.26.4 ]]',
        '"$("$go_bin" version)"',
        'requested_profile="${CPA_COMPAT_PROFILE:-primary}"',
        'require_latest="${CPA_COMPAT_REQUIRE_LATEST:-0}"',
        "CPA_COMPAT_REQUIRE_LATEST must be 0 or 1",
        "CPA_COMPAT_REQUIRE_LATEST=1 requires CPA_COMPAT_VERIFY_REMOTE=1",
        "profiles=(primary)",
        f"cpa_version='{CPA_CURRENT_VERSION}'",
        f"cpa_commit='{CPA_CURRENT_COMMIT}'",
        f"cpa_module_sum='{CPA_CURRENT_MODULE_SUM}'",
        f"cpa_go_mod_sum='{CPA_CURRENT_GO_MOD_SUM}'",
        "root_mod_flags=()",
        "contract_mod_flags=()",
        "contract_modfile='go.mod'",
        "for attempt in 1 2 3; do",
        "timeout --signal=KILL 30s git",
        '-C "$git_identity_dir"',
        "-c http.version=HTTP/1.1",
        "-c http.lowSpeedLimit=1 -c http.lowSpeedTime=30",
        'ls-remote --refs "$cpa_origin_git_url" "refs/tags/$tag"',
        'expected="${cpa_commit}"$\'\\t\'"refs/tags/$tag"',
        '[[ "$refs" == "$expected" ]]',
        'if [[ "$attempt" != 3 ]]; then',
        "sleep 3",
        "after 3 bounded attempts",
        "CPA lightweight tag identity mismatch",
        "pinned module Origin and sums remain required",
        '"$download_sum" == "$cpa_module_sum"',
        '"$download_go_mod_sum" == "$cpa_go_mod_sum"',
        ".Origin.VCS and .Origin.URL and .Origin.Hash and .Origin.Ref",
        '"$download_origin_vcs" == git',
        '"$download_origin_url" == "$cpa_origin_url"',
        '"$download_origin_hash" == "$cpa_commit"',
        '"$download_origin_ref" == "refs/tags/$cpa_version"',
        '"$cpa_module/sdk/pluginabi"',
        '"$cpa_module/sdk/pluginapi"',
    ):
        if required not in text:
            raise ContractError(
                f"fixed CPA primary verification must bind the exact lightweight tag through Git origin and selected Go toolchain: {source}"
            )
    toolchain_selection_order = (
        "export GOTOOLCHAIN=go1.26.4",
        'selected_go_root="$("$go_launcher" -C "$root" env GOROOT)"',
        'go_bin="$selected_go_root/bin/go"',
        "export GOTOOLCHAIN=local",
        'selected_go_version="$("$go_bin" env GOVERSION)"',
    )
    toolchain_positions = [text.find(marker) for marker in toolchain_selection_order]
    if any(text.count(marker) != 1 for marker in toolchain_selection_order) or (
        toolchain_positions != sorted(toolchain_positions)
    ):
        raise ContractError(
            f"CPA selected Go toolchain must resolve exact go1.26.4 before freezing GOTOOLCHAIN=local and isolating module caches: {source}"
        )
    latest_body = shell_function_body(text, "resolve_remote_latest_release_tag", source)
    for required in (
        "timeout --signal=KILL 60s curl",
        "--fail --silent --show-error --location --http1.1",
        "--retry 2 --retry-delay 2 --retry-max-time 55",
        "--retry-connrefused --retry-all-errors",
        "--connect-timeout 10 --max-time 18",
        "--header 'Accept: application/vnd.github+json'",
        "--header 'X-GitHub-Api-Version: 2022-11-28'",
        "--header 'User-Agent: cyber-abuse-guard-cpa-compat'",
        '"$cpa_latest_release_api"',
        "'.tag_name | select(type == \"string\" and length > 0)'",
    ):
        if required not in latest_body:
            raise ContractError(
                f"optional CPA latest verification must fail closed with bounded retries on the official Release identity: {source}"
            )
    latest_control_flow = (
        "verify_primary_latest=0",
        'if [[ "$profile" == primary ]]; then',
        "verify_primary_latest=1",
        'if [[ "$verify_remote" == 1 && "$require_latest" == 1 && "$verify_primary_latest" == 1 ]]; then',
        "set_profile_identity primary",
        'resolved_latest_tag="$(resolve_remote_latest_release_tag)"',
        '[[ "$resolved_latest_tag" == "$cpa_version" ]]',
        "CPA primary is no longer the latest official release",
        "CPA latest release identity PASS",
    )
    if any(marker not in text for marker in latest_control_flow):
        raise ContractError(
            f"CPA optional latest verification must bind {CPA_CURRENT_VERSION} to the official latest Release when explicitly requested: {source}"
        )
    if (
        text.count(CPA_COMPAT_FINAL_OUTPUT_CONTRACT) != 1
        or "remote_latest_and_tag_verified" in text
        or "remote_latest_and_tag_check" in text
    ):
        raise ContractError(
            f"CPA primary output must distinguish the pinned tag proof from the optional latest Release proof: {source}"
        )
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != CPA_COMPAT_SCRIPT_SHA256:
        raise ContractError(
            f"CPA primary script must match the exact reviewed remote-verification contract: {source}"
        )


def validate_ci_workflow(text: str, source: Path) -> None:
    sparse_sets = validate_workflow_safety(text, source)
    if not sparse_sets or any(patterns != ROUND9_SPARSE_PATTERNS for patterns in sparse_sets):
        raise ContractError(
            "CI must exclude both frozen Round 9 independent corpora in every checkout"
        )
    document = parse_workflow_yaml(text, source)
    validate_sensitive_workflow_expressions(
        document,
        source,
        allowed_token_paths=set(),
        allowed_identity_expressions=CI_ALLOWED_GITHUB_IDENTITY_EXPRESSIONS,
    )
    root = yaml_mapping(document, source, "root")
    jobs = yaml_mapping(root.get("jobs"), source, "jobs")
    quality = yaml_mapping(
        jobs.get("quality-and-artifacts"), source, "jobs.quality-and-artifacts"
    )
    steps = yaml_sequence(
        quality.get("steps"), source, "jobs.quality-and-artifacts.steps"
    )
    matches: list[tuple[int, Node, dict[str, Node]]] = []
    for index, step_node in enumerate(steps):
        step_path = f"jobs.quality-and-artifacts.steps[{index}]"
        step = yaml_mapping(step_node, source, step_path)
        if "name" in step and yaml_scalar(step["name"], source, f"{step_path}.name") == (
            f"CPA {CPA_CURRENT_VERSION} pinned source API and SDK contract"
        ):
            matches.append((index, step_node, step))
    if len(matches) != 1:
        raise ContractError(
            f"CI must contain exactly one reviewed CPA {CPA_CURRENT_VERSION} pinned source API and SDK step"
        )

    historical_matches: list[tuple[int, Node, dict[str, Node]]] = []
    for index, step_node in enumerate(steps):
        step_path = f"jobs.quality-and-artifacts.steps[{index}]"
        step = yaml_mapping(step_node, source, step_path)
        if "name" in step and yaml_scalar(step["name"], source, f"{step_path}.name") == (
            "Historical Round 8 counted-Mock regression"
        ):
            historical_matches.append((index, step_node, step))
    if len(historical_matches) != 1:
        raise ContractError(
            "CI must keep exactly one isolated historical Round 8 counted-Mock step"
        )
    historical_index, historical_node, historical_step = historical_matches[0]
    historical_path = f"jobs.quality-and-artifacts.steps[{historical_index}]"
    require_yaml_keys(historical_node, ("name", "run"), source, historical_path)
    historical_run = yaml_scalar(
        historical_step["run"], source, f"{historical_path}.run"
    )
    if historical_run != "make round8-counted-mock-historical-regression":
        raise ContractError(
            "CI historical Round 8 counted-Mock step must call only its isolated target"
        )

    index, cpa_step_node, cpa_step = matches[0]
    cpa_path = f"jobs.quality-and-artifacts.steps[{index}]"
    require_yaml_keys(cpa_step_node, ("name", "env", "run"), source, cpa_path)
    if exact_string_mapping(cpa_step["env"], source, f"{cpa_path}.env") != (
        ("CPA_COMPAT_PROFILE", "primary"),
        ("CPA_COMPAT_VERIFY_REMOTE", "1"),
        ("CPA_COMPAT_REQUIRE_LATEST", "0"),
    ):
        raise ContractError(
            f"CI CPA step must keep the {CPA_CURRENT_VERSION} primary profile, exact remote verification, and pinned-lane latest opt-out"
        )
    require_yaml_scalar(
        cpa_step["run"],
        "make cpa-latest-compat",
        source,
        f"{cpa_path}.run",
    )
    current_identity_markers = (
        f"integration_summary=CPA {CPA_CURRENT_VERSION} source/fail-open, SDK ABI/API, and Linux Host .so load checks completed",
        f"cpa_primary_identity={CPA_CURRENT_VERSION}@{CPA_CURRENT_COMMIT}",
    )
    if any(text.count(marker) != 1 for marker in current_identity_markers):
        raise ContractError("CI must report the exact current CPA source and commit identity")

    fuzz_job = yaml_mapping(jobs.get("fuzz-long"), source, "jobs.fuzz-long")
    fuzz_steps = yaml_sequence(
        fuzz_job.get("steps"), source, "jobs.fuzz-long.steps"
    )
    fuzz_matches: list[tuple[int, Node, dict[str, Node]]] = []
    collector_matches: list[tuple[int, Node, dict[str, Node]]] = []
    uploader_matches: list[tuple[int, Node, dict[str, Node]]] = []
    for step_index, step_node in enumerate(fuzz_steps):
        step_path = f"jobs.fuzz-long.steps[{step_index}]"
        step = yaml_mapping(step_node, source, step_path)
        if "id" in step:
            step_id = yaml_scalar(step["id"], source, f"{step_path}.id")
            if step_id == "fuzz":
                fuzz_matches.append((step_index, step_node, step))
            elif step_id == "collect_fuzz":
                collector_matches.append((step_index, step_node, step))
        if "name" in step and yaml_scalar(step["name"], source, f"{step_path}.name") == (
            "Upload Go fuzz failure corpus"
        ):
            uploader_matches.append((step_index, step_node, step))
    if len(fuzz_matches) != 1 or len(collector_matches) != 1 or len(uploader_matches) != 1:
        raise ContractError(
            "CI fuzz failure artifact flow must contain one fuzz, collector, and uploader step"
        )
    fuzz_index, fuzz_node, _ = fuzz_matches[0]
    collector_index, collector_node, collector = collector_matches[0]
    uploader_index, uploader_node, uploader = uploader_matches[0]
    if not fuzz_index < collector_index < uploader_index:
        raise ContractError("CI fuzz failure artifact steps must preserve reviewed order")
    require_yaml_keys(fuzz_node, ("id", "run"), source, "jobs.fuzz-long.steps.fuzz")
    require_yaml_keys(
        collector_node,
        ("name", "id", "if", "run"),
        source,
        "jobs.fuzz-long.steps.collect_fuzz",
    )
    require_yaml_scalar(
        collector["if"],
        "${{ failure() && steps.fuzz.outcome == 'failure' }}",
        source,
        "jobs.fuzz-long.steps.collect_fuzz.if",
    )
    require_yaml_keys(
        uploader_node,
        ("name", "if", "uses", "with"),
        source,
        "jobs.fuzz-long.steps.upload_fuzz",
    )
    require_yaml_scalar(
        uploader["if"],
        "${{ failure() && steps.fuzz.outcome == 'failure' && steps.collect_fuzz.outcome == 'success' }}",
        source,
        "jobs.fuzz-long.steps.upload_fuzz.if",
    )
    require_yaml_scalar(
        uploader["uses"],
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        source,
        "jobs.fuzz-long.steps.upload_fuzz.uses",
    )
    if re.search(r"(?m)^\s+(?:GH_TOKEN|GITHUB_TOKEN):", text):
        raise ContractError("CI may not expose a repository token to checked-out source")


def shell_function_body(text: str, name: str, source: Path) -> str:
    match = re.search(rf"(?ms)^{re.escape(name)}\(\) \{{\n(.*?)^\}}(?:\n|\Z)", text)
    if not match:
        raise ContractError(f"release helper lacks reviewed function {name}: {source}")
    return match.group(1)


def validate_rc_source_archive_transient_guard(text: str, source: Path) -> None:
    body = shell_function_body(text, "create_rc_source_archive", source)
    local_sandbox_pathspec = "    ':(exclude,glob).round9-local-sandbox/**'"
    declaration = (
        "  local transient_path_pattern='"
        + RC_SOURCE_ARCHIVE_TRANSIENT_PATH_PATTERN
        + "'"
    )
    test_binary_declaration = (
        "  local test_binary_path_pattern='"
        + RC_SOURCE_ARCHIVE_TEST_BINARY_PATH_PATTERN
        + "'"
    )
    safe_test_source_declaration = (
        "  local safe_test_source_pattern='"
        + RC_SOURCE_ARCHIVE_SAFE_TEST_SOURCE_PATTERN
        + "'"
    )
    backup_binary_archive_declaration = (
        "  local backup_binary_archive_path_pattern='"
        + RC_SOURCE_ARCHIVE_BACKUP_BINARY_ARCHIVE_PATH_PATTERN
        + "'"
    )
    secret_key_declaration = (
        "  local secret_key_path_pattern='"
        + RC_SOURCE_ARCHIVE_SECRET_KEY_PATH_PATTERN
        + "'"
    )
    local_sandbox_declaration = (
        "  local local_sandbox_path_pattern='"
        + RC_SOURCE_ARCHIVE_LOCAL_SANDBOX_PATH_PATTERN
        + "'"
    )
    if body.count(declaration) != 1 or body.count("transient_path_pattern=") != 1:
        raise ContractError(
            "RC source archive transient-artifact pattern differs from the reviewed contract"
        )
    if (
        body.count(test_binary_declaration) != 1
        or body.count("test_binary_path_pattern=") != 1
        or body.count(safe_test_source_declaration) != 1
        or body.count("safe_test_source_pattern=") != 1
    ):
        raise ContractError(
            "RC source archive test-binary allow boundary differs from the reviewed contract"
        )
    if (
        body.count(backup_binary_archive_declaration) != 1
        or body.count("backup_binary_archive_path_pattern=") != 1
    ):
        raise ContractError(
            "RC source archive backup/binary/archive pattern differs from the reviewed contract"
        )
    if body.count(secret_key_declaration) != 1 or body.count("secret_key_path_pattern=") != 1:
        raise ContractError(
            "RC source archive SSH-key pattern differs from the reviewed contract"
        )
    if (
        body.count(local_sandbox_declaration) != 1
        or body.count("local_sandbox_path_pattern=") != 1
    ):
        raise ContractError(
            "RC source archive local-sandbox pattern differs from the reviewed contract"
        )
    if body.count(RC_SOURCE_ARCHIVE_SECRET_GUARD_BLOCK) != 1:
        raise ContractError(
            "RC source archive must fail closed on secret-key and local-sandbox paths"
        )
    if body.count(local_sandbox_pathspec) != 1:
        raise ContractError(
            "RC source archive must explicitly exclude the Round 9 local sandbox"
        )
    if body.count(RC_SOURCE_ARCHIVE_TRANSIENT_GUARD_BLOCK) != 1:
        raise ContractError(
            "RC source archive must fail closed on profiles, test binaries, executables, and classifier candidates"
        )

    transient_pattern = re.compile(
        RC_SOURCE_ARCHIVE_TRANSIENT_PATH_PATTERN, re.IGNORECASE
    )
    test_binary_pattern = re.compile(
        RC_SOURCE_ARCHIVE_TEST_BINARY_PATH_PATTERN, re.IGNORECASE
    )
    safe_test_source_pattern = re.compile(
        RC_SOURCE_ARCHIVE_SAFE_TEST_SOURCE_PATTERN, re.IGNORECASE
    )
    backup_binary_archive_pattern = re.compile(
        RC_SOURCE_ARCHIVE_BACKUP_BINARY_ARCHIVE_PATH_PATTERN, re.IGNORECASE
    )
    secret_key_pattern = re.compile(
        RC_SOURCE_ARCHIVE_SECRET_KEY_PATH_PATTERN, re.IGNORECASE
    )
    local_sandbox_pattern = re.compile(
        RC_SOURCE_ARCHIVE_LOCAL_SANDBOX_PATH_PATTERN, re.IGNORECASE
    )

    def forbidden_path(relative: str) -> bool:
        path = f"cyber-abuse-guard-fixture/{relative}"
        return (
            backup_binary_archive_pattern.search(path) is not None
            or transient_pattern.search(path) is not None
            or secret_key_pattern.search(path) is not None
            or local_sandbox_pattern.search(path) is not None
            or (
                test_binary_pattern.search(path) is not None
                and safe_test_source_pattern.search(path) is None
            )
        )

    for relative in RC_SOURCE_ARCHIVE_FORBIDDEN_PATH_FIXTURES:
        if not forbidden_path(relative):
            raise ContractError(
                "RC source archive reviewed forbidden-path semantics are incomplete: "
                + relative
            )
    for relative in RC_SOURCE_ARCHIVE_SAFE_PATH_FIXTURES:
        if forbidden_path(relative):
            raise ContractError(
                "RC source archive reviewed safe-source boundary is overbroad: "
                + relative
            )

    ordered_markers = (
        declaration,
        test_binary_declaration,
        safe_test_source_declaration,
        backup_binary_archive_declaration,
        secret_key_declaration,
        local_sandbox_declaration,
        local_sandbox_pathspec,
        '  listing="$(tar -tzf "$temporary")"',
        RC_SOURCE_ARCHIVE_SECRET_GUARD_BLOCK,
        RC_SOURCE_ARCHIVE_TRANSIENT_GUARD_BLOCK,
        '  mv -f -- "$temporary" "$output_dir/$source_archive"',
    )
    positions = tuple(body.find(marker) for marker in ordered_markers)
    if any(position < 0 for position in positions) or positions != tuple(sorted(positions)):
        raise ContractError(
            "RC source archive transient-artifact guard must run on the final listing before publication"
        )


def validate_release_build_metadata_script(text: str, source: Path) -> None:
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != RELEASE_BUILD_METADATA_SCRIPT_SHA256
    ):
        raise ContractError("release build metadata script differs from reviewed schema-4 contract")
    required_once = (
        'go_version="$($go_bin env GOVERSION)"',
        'cc_command="$($go_bin env CC)"',
        'gcc_version="$(gcc -dumpfullversion -dumpversion)"',
        'gcc_target="$(gcc -dumpmachine)"',
        'binutils_ld_version="$(LC_ALL=C ld --version | sed -n \'1p\')"',
        'glibc_version="$(LC_ALL=C ldd --version 2>&1 | sed -n \'1p\')"',
        'builder_image="${RC_BUILDER_IMAGE:-NOT_PROVIDED}"',
        'builder_image_digest="${RC_BUILDER_IMAGE_DIGEST:-NOT_PROVIDED}"',
        'builder_reference="${RC_BUILDER_REFERENCE:-NOT_PROVIDED}"',
        'runner_label="${RC_RUNNER_LABEL:-NOT_PROVIDED}"',
        'runner_os="${RC_RUNNER_OS:-NOT_PROVIDED}"',
        'runner_arch="${RC_RUNNER_ARCH:-NOT_PROVIDED}"',
        'runner_environment="${RC_RUNNER_ENVIRONMENT:-NOT_PROVIDED}"',
        'runner_name="${RC_RUNNER_NAME:-NOT_PROVIDED}"',
        'runner_image_os="${RC_RUNNER_IMAGE_OS:-${ImageOS:-NOT_PROVIDED}}"',
        'runner_image_version="${RC_RUNNER_IMAGE_VERSION:-${ImageVersion:-NOT_PROVIDED}}"',
        'if [[ "${RELEASE_RC_BUILD:-0}" == 1 ]]; then',
        f"trusted_builder_image='{RC_BUILDER_IMAGE}'",
        f"trusted_builder_image_digest='{RC_BUILDER_IMAGE_DIGEST}'",
        'trusted_builder_reference="${trusted_builder_image}@${trusted_builder_image_digest}"',
        f"reproducible_runner_name='{RC_REPRODUCIBLE_RUNNER_NAME}'",
        "unobservable_runner_image='UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER'",
        "canonical_builder_image_pattern='^docker\\.io/([a-z0-9]+([._-][a-z0-9]+)*/)*[a-z0-9]+([._-][a-z0-9]+)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'",
        '[[ "$builder_image" =~ $canonical_builder_image_pattern ]]',
        '[[ "$builder_image_digest" =~ ^sha256:[0-9a-f]{64}$ ]]',
        '[[ "$builder_reference" == "${builder_image}@${builder_image_digest}" ]]',
        '"$builder_reference" == "$trusted_builder_reference"',
        '[[ "$runner_label" == ubuntu-24.04 ]]',
        '[[ "$runner_os" == Linux ]]',
        '[[ "$runner_arch" == X64 ]]',
        '[[ "$runner_environment" == github-hosted ]]',
        '[[ "$runner_name" == "$reproducible_runner_name" ]] || \\',
        '[[ "$runner_image_os" == "$unobservable_runner_image" && \\',
        '"$runner_image_version" == "$unobservable_runner_image" ]] || \\',
        '--arg runner_label "$runner_label" \\',
        '--arg runner_os "$runner_os" \\',
        '--arg runner_arch "$runner_arch" \\',
        '--arg runner_environment "$runner_environment" \\',
        '--arg runner_name "$runner_name" \\',
        '--arg runner_image_os "$runner_image_os" \\',
        '--arg runner_image_version "$runner_image_version" \\',
        "schema_version: 4,",
        "go_version: $go_version,",
        'goos: "linux",',
        'goarch: "amd64",',
        "cgo_enabled: true,",
        "cc_command: $cc_command,",
        "gcc_version: $gcc_version,",
        "gcc_target: $gcc_target,",
        "binutils_ld_version: $binutils_ld_version,",
        "glibc_version: $glibc_version,",
        "builder_image: $builder_image,",
        "builder_image_digest: $builder_image_digest,",
        "builder_reference: $builder_reference,",
        "runner_label: $runner_label,",
        "runner_os: $runner_os,",
        "runner_arch: $runner_arch,",
        "runner_environment: $runner_environment,",
        "runner_name: $runner_name,",
        "runner_image_os: $runner_image_os,",
        "runner_image_version: $runner_image_version",
    )
    if any(text.count(marker) != 1 for marker in required_once):
        raise ContractError(
            "release build metadata must retain the exact schema-4 toolchain, builder, and runner identity fields"
        )
    ordered_markers = (
        'go_version="$($go_bin env GOVERSION)"',
        'cc_command="$($go_bin env CC)"',
        'gcc_version="$(gcc -dumpfullversion -dumpversion)"',
        'builder_image="${RC_BUILDER_IMAGE:-NOT_PROVIDED}"',
        'builder_reference="${RC_BUILDER_REFERENCE:-NOT_PROVIDED}"',
        'runner_label="${RC_RUNNER_LABEL:-NOT_PROVIDED}"',
        'runner_name="${RC_RUNNER_NAME:-NOT_PROVIDED}"',
        'runner_image_version="${RC_RUNNER_IMAGE_VERSION:-${ImageVersion:-NOT_PROVIDED}}"',
        'if [[ "${RELEASE_RC_BUILD:-0}" == 1 ]]; then',
        f"reproducible_runner_name='{RC_REPRODUCIBLE_RUNNER_NAME}'",
        "unobservable_runner_image='UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER'",
        '[[ "$runner_label" == ubuntu-24.04 ]]',
        '[[ "$runner_image_os" == "$unobservable_runner_image" && \\',
        "jq -n \\",
        "schema_version: 4,",
        "runner_label: $runner_label,",
        "runner_image_version: $runner_image_version",
        'mv -f -- "$temporary" "$output_dir/build-metadata.json"',
    )
    positions = tuple(text.find(marker) for marker in ordered_markers)
    if any(position < 0 for position in positions) or positions != tuple(sorted(positions)):
        raise ContractError(
            "release build metadata must collect and validate immutable builder identity before emitting schema 4"
        )


def validate_rc_reproducible_release_asset_contract(text: str, source: Path) -> None:
    required_once = (
        (
            "round8)\n"
            "    canonical_repository='yujianwudi/cyber-abuse-guard'\n"
            f"    cpa_version='{CPA_ROUND8_VERSION}'\n"
            f"    cpa_commit='{CPA_ROUND8_COMMIT}'\n"
            "    ;;"
        ),
        (
            "round9)\n"
            "    canonical_repository='yujianwudi/cyber-abuse-guard-next'\n"
            f"    cpa_version='{CPA_CURRENT_VERSION}'\n"
            f"    cpa_commit='{CPA_CURRENT_COMMIT}'\n"
            "    ;;"
        ),
        'cpa_gate_key="rc_gate.cpa_${cpa_version}_primary_source_compatibility=PASS"',
        f"runner_name_reproducible='{RC_REPRODUCIBLE_RUNNER_NAME}'",
        f"workflow_run_reproducible='{RC_REPRODUCIBLE_WORKFLOW_RUN}'",
        f"workflow_attempt_reproducible='{RC_REPRODUCIBLE_WORKFLOW_ATTEMPT}'",
        '[[ "$runner_name" == "$runner_name_reproducible" ]] || \\',
        "round8) rc_summary_heading='CPA Cyber Abuse Guard v0.16-rc.2 canonical internal Linux release gates' ;;",
        'round9) rc_summary_heading="CPA Cyber Abuse Guard v${RELEASE_ARTIFACT_VERSION} Round 9 canonical Linux release gates" ;;',
        '"$rc_summary_heading" \\',
        "'summary_schema=1' \\",
        "'dynamic_stdout_included=false' \\",
        "'wall_clock_timing_included=false' \\",
        "'benchmark_measurements_included=false'",
        'cmp -s "$summary_input" "$expected_summary" || \\',
        'release_die "RC test summary must exactly match the canonical timing-free gate record"',
        'printf -- \'- Release workflow run identity: %s\\n\' "$workflow_run_reproducible"',
        'printf -- \'- Release workflow attempt identity: %s\\n\' "$workflow_attempt_reproducible"',
        '--arg run_id "$workflow_run_reproducible" \\',
        '--arg run_attempt "$workflow_attempt_reproducible" \\',
        "run_id: $run_id,",
        "run_attempt: $run_attempt",
    )
    if any(text.count(marker) != 1 for marker in required_once):
        raise ContractError(
            "RC release assets must retain the exact lane identities, canonical summary, and stable ephemeral-runner contract"
        )
    if text.count("cpa_gate_key") != 2:
        raise ContractError(
            "RC release assets must derive and consume exactly one lane-specific CPA gate key"
        )
    if text.count("GITHUB_RUN_ID") != 1 or text.count("GITHUB_RUN_ATTEMPT") != 1:
        raise ContractError(
            "RC release assets may validate the current workflow run but must not serialize it"
        )
    for forbidden in (
        '--argjson run_id "$GITHUB_RUN_ID"',
        '--argjson run_attempt "$GITHUB_RUN_ATTEMPT"',
        '"$GITHUB_REPOSITORY" "$GITHUB_RUN_ID"',
        'runner_name_reproducible="${RC_RUNNER_NAME',
    ):
        if forbidden in text:
            raise ContractError(
                "RC release assets contain a cross-dispatch dynamic workflow identity"
            )
    for literal_gate in (
        f"rc_gate.cpa_{CPA_ROUND8_VERSION}_primary_source_compatibility=PASS",
        f"rc_gate.cpa_{CPA_CURRENT_VERSION}_primary_source_compatibility=PASS",
    ):
        if literal_gate in text:
            raise ContractError(
                "RC release assets must derive the CPA gate key from the reviewed lane identity"
            )
    summary_markers = (
        "round8) rc_summary_heading='CPA Cyber Abuse Guard v0.16-rc.2 canonical internal Linux release gates' ;;",
        'round9) rc_summary_heading="CPA Cyber Abuse Guard v${RELEASE_ARTIFACT_VERSION} Round 9 canonical Linux release gates" ;;',
        '"$rc_summary_heading"',
        "'summary_schema=1'",
        '"commit=$RELEASE_GIT_COMMIT"',
        '"tree=$RELEASE_GIT_TREE"',
        '"exact_main_ci_run=$RC_CI_RUN_ID"',
        '"exact_main_ci_attempt=$RC_CI_RUN_ATTEMPT"',
        "'rc_gate.safe_contract=PASS'",
        "'rc_gate.full_linux_quality=PASS'",
        '"$cpa_gate_key"',
        "'rc_gate.rc_integration=PASS'",
        "'rc_gate.clean_tree=PASS'",
        "'dynamic_stdout_included=false'",
        "'wall_clock_timing_included=false'",
        "'benchmark_measurements_included=false'",
        '} >"$expected_summary"',
        'cmp -s "$summary_input" "$expected_summary"',
    )
    positions = tuple(text.find(marker) for marker in summary_markers)
    if any(position < 0 for position in positions) or positions != tuple(sorted(positions)):
        raise ContractError(
            "RC canonical test summary must use the reviewed order and reject dynamic stdout"
        )


def validate_release_mode_contracts(root: Path) -> None:
    common_path = root / "scripts/release-common.sh"
    if not common_path.exists():
        return
    common = read_regular_text(common_path, root)
    required_git_environment_reset = (
        "unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR \\\n"
        "  GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE"
    )
    if required_git_environment_reset not in common:
        raise ContractError(
            "release helpers must clear inherited Git repository-routing variables"
        )
    metadata_path = root / RELEASE_BUILD_METADATA_SCRIPT
    if metadata_path.exists() or metadata_path.is_symlink():
        metadata_text = read_regular_text(metadata_path, root)
        validate_release_build_metadata_script(metadata_text, metadata_path)
    for script_name, expected_hash in EXTERNAL_ATTESTATION_SCRIPT_SHA256.items():
        path = root / "scripts" / script_name
        text = read_regular_text(path, root)
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != expected_hash:
            raise ContractError(
                f"external release attestation script differs from reviewed contract: {script_name}"
            )
    round8_paths = [root / relative for relative in ROUND8_HOST_REVIEWED_SCRIPT_SHA256]
    if any(path.exists() or path.is_symlink() for path in round8_paths):
        for relative, expected_hash in ROUND8_HOST_REVIEWED_SCRIPT_SHA256.items():
            path = root / relative
            text = read_regular_text(path, root)
            if hashlib.sha256(text.encode("utf-8")).hexdigest() != expected_hash:
                raise ContractError(
                    f"Round8 Host runner script differs from reviewed contract: {relative}"
                )
    formal_body = shell_function_body(
        common, "release_assert_formal_build", common_path
    )
    if (
        '[[ "$RELEASE_BUILD_KIND" == formal ]]' not in formal_body
        or '[[ "$RELEASE_DIRTY" == false ]]' not in formal_body
    ):
        raise ContractError(
            "release_assert_formal_build must reject candidate and dirty build modes"
        )
    candidate_body = shell_function_body(
        common, "release_assert_candidate_build", common_path
    )
    for required in (
        '[[ "$RELEASE_BUILD_KIND" == candidate ]]',
        '[[ "$RELEASE_DIRTY" == false ]]',
        'if git -C "$RELEASE_ROOT" show-ref --verify --quiet "refs/tags/$formal_tag"; then',
        'release_die "candidate builds are forbidden after any formal tag ref $formal_tag exists"',
    ):
        if required not in candidate_body:
            raise ContractError(
                "release_assert_candidate_build must stay clean, exact-mode, and pre-formal-tag only"
            )

    rc_body = shell_function_body(common, "release_assert_rc_build", common_path)
    for required in (
        '[[ "$RELEASE_BUILD_KIND" == rc ]]',
        '[[ "$RELEASE_DIRTY" == false ]]',
        '[[ "$RELEASE_RC_TAG" == "v$RELEASE_ARTIFACT_VERSION" ]]',
        'if git -C "$RELEASE_ROOT" show-ref --verify --quiet "refs/tags/$formal_tag"; then',
        'release_die "RC builds are forbidden after the formal tag $formal_tag exists"',
    ):
        if required not in rc_body:
            raise ContractError(
                "release_assert_rc_build must stay clean, exact-tagged, and pre-formal-tag only"
            )

    rc_script_path = root / "scripts/round6-rc-artifacts.sh"
    if rc_script_path.exists():
        rc_script = read_regular_text(rc_script_path, root)
        if hashlib.sha256(rc_script.encode("utf-8")).hexdigest() != RC_RELEASE_SCRIPT_SHA256:
            raise ContractError("RC release artifact script differs from reviewed contract")
        if "\\$" + "{" in rc_script:
            raise ContractError(
                "RC release artifact script contains an escaped Bash parameter expansion"
            )
        validate_rc_reproducible_release_asset_contract(rc_script, rc_script_path)
        if rc_script.count("    docs/ROUND8_HOST_RUNNER.md\n") != 1:
            raise ContractError(
                "RC audit bundle must contain the Round8 Host runner operating guide"
            )
        if rc_script.count("      docs/ROUND9_HOST_RUNNER.md\n") != 1:
            raise ContractError(
                "Round 9 RC audit bundle must contain the fixed-port Host operating guide"
            )
        for marker in (
            "HOST_EVIDENCE_ATTESTED_PROTECTED_WORKFLOW / SANDBOX_IDENTITY_AND_LOCALITY_VERIFIED",
            "GITHUB_ATTESTATION_VERIFIED / PROTECTED_HOST_WORKFLOW / COUNTED_MOCK_ONLY",
            "ATTESTED_PROTECTED_HOST_WORKFLOW_ARTIFACT",
            "SIGNER_WORKFLOW_REF_COMMIT_RUN_ARTIFACT_DIGEST_CHALLENGE_AND_SANDBOX_LOCALITY_VERIFIED",
            "The Host evidence is produced and signed by the protected Round 8 Host workflow",
        ):
            if marker not in rc_script:
                raise ContractError(
                    "RC release artifact script must preserve the protected attested Host evidence boundary"
                )
        for marker in (
            "Round 9 RC lane requires v0.16-rc.4",
            "rc_manifest_schema=6",
            "RC_ROUND9_DEVELOPMENT_EVIDENCE_INPUT",
            "validate_round9_development_evidence",
            "validate_round9_external_evaluation",
            "Round 9 publication consumes signed external evaluation, not legacy Host evidence inputs",
            'round9-external-evaluation/v3',
            'round9-external-counted-mock/v1',
            'round9-public-counted-mock/v1',
            '.payload.public_counted_mock.total.serialized_executions == 120',
            '.payload.public_counted_mock.total.local_blocked == 80',
            '.payload.public_counted_mock.total.upstream_delta == 40',
            '.payload.public_counted_mock.total.usage_delta == 40',
            '.payload.metrics.public_counted_mock == .payload.public_counted_mock',
            '.payload.development_evidence == $development[0]',
            'expected_count=17',
            'expected_count=19',
            "testdata/round9-development-paired-malicious-v3/cases.jsonl",
            "testdata/round9-development-paired-malicious-v3/manifest.json",
            "testdata/round9-development-paired-malicious-v3/README.md",
            "testdata/round9-development-paired-malicious-v3/LABEL_AUDIT.md",
            "testdata/round9-development-paired-malicious-v3/LABEL_AUDIT_REJECTED_DRAFT1.md",
            "docs/ROUND9_AUDIT_SCHEMA_V6.md",
            "docs/ROUND9_HOST_RUNNER.md",
            "docs/ROUND9_OPERATOR_ROLLOUT.md",
            "docs/reports/ROUND9_EXECUTION_RECORD.md",
            "Public adversarial v13",
            'initial_mode: "audit"',
            'phase_order: ["audit", "balanced", "strict"]',
            'status_required_after_each_phase_transition: true',
            'mode_switch_authenticated: true',
            'hmac_sha256_challenge_sequential_phase_order_v3',
            'round9-external-cpa-runtime-checks/v1',
            '.payload.counted_mock.not_observed == []',
            '.payload.metrics.runtime_checks ==',
            'schema_version: $manifest_schema',
            'round9: {',
            'development_evidence: $round9_development_evidence',
            'counted_mock: $round9_counted_mock',
            'external_evaluation: $round9_external_evaluation',
            'external_ledger_proof: $round9_external_ledger_proof',
        ):
            if marker not in rc_script:
                raise ContractError(
                    "RC release artifact script must preserve the Round 9 schema-6 external-evaluation contract"
                )
        if rc_script.count("Public adversarial v13") != 2:
            raise ContractError(
                "RC release artifact script must bind public adversarial v13 in both release summaries"
            )
        if "Public adversarial v12" in rc_script:
            raise ContractError(
                "RC release artifact script retains the stale public adversarial v12 label"
            )
        fixed_binding = 'host_ip: "127.0.0.1", host_port: 18394, container_port: 8317'
        if rc_script.count(fixed_binding) != 2:
            raise ContractError(
                "Round 9 RC artifact script must bind the fixed 127.0.0.1:18394 CPA listener twice"
            )
        if "round9-host-evidence" in rc_script:
            raise ContractError(
                "Round 9 RC artifact script must not restore the retired Host-evidence sidecar"
            )
        validate_rc_source_archive_transient_guard(rc_script, rc_script_path)

    for script_name in FORMAL_OPERATION_SCRIPTS:
        path = root / "scripts" / script_name
        text = read_regular_text(path, root)
        commands = tuple(
            command.strip()
            for command in logical_shell_commands(text)
            if command.strip() and not command.lstrip().startswith("#")
        )
        required = ("release_init", "release_assert_tag", "release_assert_formal_build")
        positions: list[int] = []
        for command in required:
            matches = [index for index, actual in enumerate(commands) if actual == command]
            if len(matches) != 1:
                raise ContractError(
                    f"formal operation {script_name} must invoke {command} exactly once"
                )
            positions.append(matches[0])
        if positions != sorted(positions):
            raise ContractError(
                f"formal operation {script_name} must assert tag then formal build before work"
            )
        if any(
            "RELEASE_CANDIDATE_BUILD" in command or "RELEASE_RC_" in command
            for command in commands
        ):
            raise ContractError(
                f"formal operation {script_name} may not enable candidate or RC build mode"
            )
        if script_name == "formal-release.sh":
            override_loop = (
                "for override in "
                + " ".join(FORMAL_RELEASE_DOCUMENT_OVERRIDE_ENV)
                + "; do"
            )
            override_guard = 'if [[ -n "${!override+x}" ]]; then'
            override_failure = (
                'release_die "formal release forbids release document override '
                'environment: $override"'
            )
            document_gate = '"$root/scripts/release-doc-consistency.sh"'
            override_contract = (
                override_loop,
                override_guard,
                override_failure,
                "fi",
                "done",
                document_gate,
            )
            matches = [
                index
                for index in range(len(commands) - len(override_contract) + 1)
                if commands[index : index + len(override_contract)] == override_contract
            ]
            if (
                len(matches) != 1
                or commands.count(override_loop) != 1
                or commands.count(override_guard) != 1
                or commands.count(override_failure) != 1
                or commands.count(document_gate) != 1
                or matches[0] <= positions[-1]
            ):
                raise ContractError(
                    "formal release must reject every release document override environment "
                    "before document verification"
                )

    package_path = root / "scripts/package-release.sh"
    package_text = read_regular_text(package_path, root)
    report_source = f'"$root/{FORMAL_AUDIT_REPORT_PATH}"'
    required_start = package_text.find("for required_file in \\\n")
    required_end = package_text.find("; do", required_start)
    install_start = package_text.find(
        'install -m 0644 "$root/docs/reports/TEST_REPORT.md" \\\n'
    )
    install_end = package_text.find(
        '"$bundle_stage/docs/reports/"', install_start
    )
    if (
        required_start < 0
        or required_end < 0
        or package_text[required_start:required_end].count(report_source) != 1
        or install_start < 0
        or install_end < 0
        or package_text[install_start:install_end].count(report_source) != 1
    ):
        raise ContractError(
            "formal audit bundle must require and package the public jailbreak audit report"
        )

    verify_path = root / "scripts/verify-release.sh"
    verify_text = read_regular_text(verify_path, root)
    listing_start_marker = 'expected_bundle_listing="$(cat <<EOF\n'
    listing_start = verify_text.find(listing_start_marker)
    listing_end = verify_text.find("\nEOF\n)", listing_start)
    if (
        listing_start < 0
        or listing_end < 0
        or verify_text[
            listing_start + len(listing_start_marker) : listing_end
        ].splitlines().count(FORMAL_AUDIT_REPORT_PATH)
        != 1
    ):
        raise ContractError(
            "formal audit bundle verifier must require the public jailbreak audit report"
        )

    evidence_path = root / "scripts/generate-release-evidence.sh"
    evidence_text = read_regular_text(evidence_path, root)
    if hashlib.sha256(evidence_text.encode("utf-8")).hexdigest() != GENERATE_RELEASE_EVIDENCE_SCRIPT_SHA256:
        raise ContractError(
            "release evidence generator must match the immutable attestation snapshot contract"
        )


def validate_run_hash(
    step: dict[str, Node],
    expected_hash: str,
    source: Path,
    path: str,
) -> None:
    run = yaml_scalar(step.get("run"), source, f"{path}.run")
    if hashlib.sha256(run.encode("utf-8")).hexdigest() != expected_hash:
        raise ContractError(f"workflow {path}.run must match the exact reviewed text")


def validate_formal_release_workflow(text: str, source: Path) -> None:
    document = parse_workflow_yaml(text, source)
    root = require_yaml_keys(
        document,
        ("name", "on", "permissions", "concurrency", "env", "jobs"),
        source,
        "workflow",
    )
    require_yaml_scalar(root["name"], "Release", source, "name")
    on = require_yaml_keys(root["on"], ("push",), source, "on")
    push = require_yaml_keys(on["push"], ("tags",), source, "on.push")
    tags = yaml_sequence(push["tags"], source, "on.push.tags")
    if len(tags) != 1:
        raise ContractError("formal release workflow must trigger only for exact tag v0.15")
    require_yaml_scalar(tags[0], "v0.15", source, "on.push.tags[0]")
    permissions = require_yaml_keys(
        root["permissions"], ("contents",), source, "permissions"
    )
    require_yaml_scalar(permissions["contents"], "read", source, "permissions.contents")
    concurrency = require_yaml_keys(
        root["concurrency"], ("group", "cancel-in-progress"), source, "concurrency"
    )
    require_yaml_scalar(
        concurrency["group"],
        "${{ github.workflow }}-${{ github.ref }}",
        source,
        "concurrency.group",
    )
    require_yaml_scalar(
        concurrency["cancel-in-progress"],
        "false",
        source,
        "concurrency.cancel-in-progress",
        tag="tag:yaml.org,2002:bool",
    )
    env = require_yaml_keys(
        root["env"],
        ("GO_VERSION", "VERSION", "CYCLONEDX_GOMOD_VERSION", "GOVULNCHECK_VERSION"),
        source,
        "env",
    )
    for env_name in ("GO_VERSION", "VERSION", "CYCLONEDX_GOMOD_VERSION", "GOVULNCHECK_VERSION"):
        require_yaml_scalar(env[env_name], SAFE_WORKFLOW_ENV[env_name], source, f"env.{env_name}")

    jobs = require_yaml_keys(
        root["jobs"], ("admission", "build-and-verify", "publish"), source, "jobs"
    )
    admission_path = "jobs.admission"
    admission = require_yaml_keys(
        jobs["admission"],
        ("permissions", "runs-on", "timeout-minutes", "steps"),
        source,
        admission_path,
    )
    admission_permissions = require_yaml_keys(
        admission["permissions"], ("contents",), source, f"{admission_path}.permissions"
    )
    require_yaml_scalar(
        admission_permissions["contents"],
        "read",
        source,
        f"{admission_path}.permissions.contents",
    )
    require_yaml_scalar(
        admission["runs-on"], "ubuntu-24.04", source, f"{admission_path}.runs-on"
    )
    require_yaml_scalar(
        admission["timeout-minutes"],
        "10",
        source,
        f"{admission_path}.timeout-minutes",
        tag="tag:yaml.org,2002:int",
    )
    admission_steps = yaml_sequence(admission["steps"], source, f"{admission_path}.steps")
    if len(admission_steps) != 1:
        raise ContractError("formal release admission must contain exactly one no-checkout step")
    admission_step = require_yaml_keys(
        admission_steps[0],
        ("name", "env", "run"),
        source,
        f"{admission_path}.steps[0]",
    )
    require_yaml_scalar(
        admission_step["name"],
        "Admit exact main-tip tag and attested Round6 candidate before checkout",
        source,
        f"{admission_path}.steps[0].name",
    )
    expected_admission_env = (
        ("GH_TOKEN", "${{ github.token }}"),
        ("DISPATCH_REF", "${{ github.ref }}"),
        ("DISPATCH_SHA", "${{ github.sha }}"),
        ("WORKFLOW_REF", "${{ github.workflow_ref }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    )
    if exact_string_mapping(
        admission_step["env"], source, f"{admission_path}.steps[0].env"
    ) != expected_admission_env:
        raise ContractError("formal release no-checkout admission environment changed")
    admission_run = yaml_scalar(
        admission_step["run"], source, f"{admission_path}.steps[0].run"
    )
    validate_run_hash(
        admission_step,
        FORMAL_RELEASE_STEP_RUN_SHA256[("admission", 0)],
        source,
        f"{admission_path}.steps[0]",
    )
    if re.search(r"(?i)actions/checkout@|(?:^|[\s;&|])(?:\./)?scripts/|(?:^|[\s;&|])(?:g?make)(?=\s|$)", admission_run):
        raise ContractError("formal release admission must remain no-checkout and repository-code-free")

    build_path = "jobs.build-and-verify"
    build = require_yaml_keys(
        jobs["build-and-verify"],
        ("needs", "permissions", "env", "runs-on", "timeout-minutes", "steps"),
        source,
        build_path,
    )
    require_yaml_scalar(build["needs"], "admission", source, f"{build_path}.needs")
    build_permissions = require_yaml_keys(
        build["permissions"], ("actions", "contents"), source, f"{build_path}.permissions"
    )
    require_yaml_scalar(
        build_permissions["actions"], "read", source, f"{build_path}.permissions.actions"
    )
    require_yaml_scalar(
        build_permissions["contents"], "read", source, f"{build_path}.permissions.contents"
    )
    if exact_string_mapping(build["env"], source, f"{build_path}.env") != (
        ("ROUND6_SAFE_SPARSE_BUILD", "1"),
    ):
        raise ContractError("formal release sparse-build environment changed")
    require_yaml_scalar(build["runs-on"], "ubuntu-24.04", source, f"{build_path}.runs-on")
    require_yaml_scalar(
        build["timeout-minutes"],
        "60",
        source,
        f"{build_path}.timeout-minutes",
        tag="tag:yaml.org,2002:int",
    )
    build_steps = yaml_sequence(build["steps"], source, f"{build_path}.steps")
    build_contracts = (
        (
            "Checkout tagged source and full history",
            ("name", "uses", "with"),
            "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        ),
        (
            "Set up pinned Go",
            ("name", "uses", "with"),
            "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
        ),
        ("Install native release dependencies", ("name", "run"), None),
        ("Install pinned security and SBOM tools", ("name", "run"), None),
        ("Tag, source version, and clean-tree preflight", ("name", "run"), None),
        (
            "Verify Host, audit, and independent evaluation attestation before formal gates",
            ("name", "id", "env", "run"),
            None,
        ),
        (
            "Download the immutable blocked workflow artifact",
            ("name", "uses", "with"),
            "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        ),
        (
            "Prove the blocked draft matches its immutable workflow artifact",
            ("name", "run"),
            None,
        ),
        ("Run all release gates and build artifacts", ("name", "env", "run"), None),
        ("Recheck hashes and source cleanliness", ("name", "run"), None),
        (
            "Byte-compare formal assets and bind the verified prerelease attestation",
            ("name", "env", "run"),
            None,
        ),
        (
            "Upload exact verified release artifacts",
            ("name", "uses", "with"),
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ),
    )
    if len(build_steps) != len(build_contracts):
        raise ContractError("formal release build job must contain exactly twelve reviewed steps")
    for index, (step_node, contract) in enumerate(zip(build_steps, build_contracts)):
        name, keys, action = contract
        path = f"{build_path}.steps[{index}]"
        step = require_yaml_keys(step_node, keys, source, path)
        require_yaml_scalar(step["name"], name, source, f"{path}.name")
        if action is not None:
            require_yaml_scalar(step["uses"], action, source, f"{path}.uses")
        expected_hash = FORMAL_RELEASE_STEP_RUN_SHA256.get(("build-and-verify", index))
        if expected_hash is not None:
            validate_run_hash(step, expected_hash, source, path)

    checkout = yaml_mapping(build_steps[0], source, f"{build_path}.steps[0]")
    checkout_with = require_yaml_keys(
        checkout["with"],
        (
            "fetch-depth",
            "persist-credentials",
            "filter",
            "sparse-checkout-cone-mode",
            "sparse-checkout",
        ),
        source,
        f"{build_path}.steps[0].with",
    )
    require_yaml_scalar(
        checkout_with["fetch-depth"],
        "0",
        source,
        f"{build_path}.steps[0].with.fetch-depth",
        tag="tag:yaml.org,2002:int",
    )
    require_yaml_scalar(
        checkout_with["persist-credentials"],
        "false",
        source,
        f"{build_path}.steps[0].with.persist-credentials",
        tag="tag:yaml.org,2002:bool",
    )
    require_yaml_scalar(
        checkout_with["filter"],
        "blob:none",
        source,
        f"{build_path}.steps[0].with.filter",
    )
    require_yaml_scalar(
        checkout_with["sparse-checkout-cone-mode"],
        "false",
        source,
        f"{build_path}.steps[0].with.sparse-checkout-cone-mode",
        tag="tag:yaml.org,2002:bool",
    )
    sparse = yaml_scalar(
        checkout_with["sparse-checkout"],
        source,
        f"{build_path}.steps[0].with.sparse-checkout",
    )
    if tuple(line.strip() for line in sparse.splitlines() if line.strip()) != ROUND6_SPARSE_PATTERNS:
        raise ContractError("formal release sparse checkout differs from Round6 restrictions")
    setup_go = yaml_mapping(build_steps[1], source, f"{build_path}.steps[1]")
    setup_with = require_yaml_keys(
        setup_go["with"], ("go-version", "cache"), source, f"{build_path}.steps[1].with"
    )
    require_yaml_scalar(
        setup_with["go-version"], "${{ env.GO_VERSION }}", source, f"{build_path}.steps[1].with.go-version"
    )
    require_yaml_scalar(
        setup_with["cache"],
        "true",
        source,
        f"{build_path}.steps[1].with.cache",
        tag="tag:yaml.org,2002:bool",
    )
    attestation_step = yaml_mapping(build_steps[5], source, f"{build_path}.steps[5]")
    require_yaml_scalar(
        attestation_step["id"], "candidate_gate", source, f"{build_path}.steps[5].id"
    )
    if exact_string_mapping(
        attestation_step["env"], source, f"{build_path}.steps[5].env"
    ) != (("GH_TOKEN", "${{ github.token }}"),):
        raise ContractError("formal release attestation verification env changed")
    attestation_run = yaml_scalar(
        attestation_step["run"], source, f"{build_path}.steps[5].run"
    )
    for required in (
        './scripts/verify-external-release-attestation.sh "$attestation"',
        "'CI' '.github/workflows/ci.yml' 'push'",
        "'Candidate build - NOT A RELEASE'",
        "'.github/workflows/candidate.yml' 'workflow_dispatch'",
        "'Attested prerelease - HOST, AUDIT, AND EVALUATION REQUIRED'",
        "'.github/workflows/attested-prerelease.yml' 'workflow_dispatch'",
    ):
        if required not in attestation_run:
            raise ContractError(
                "formal release must verify external attestation and every attested workflow run"
            )
    blocked_download = yaml_mapping(build_steps[6], source, f"{build_path}.steps[6]")
    blocked_download_with = require_yaml_keys(
        blocked_download["with"],
        ("name", "path", "github-token", "repository", "run-id"),
        source,
        f"{build_path}.steps[6].with",
    )
    for key, expected in (
        ("name", "round6-blocked-attested-${{ steps.candidate_gate.outputs.expected_commit }}"),
        ("path", "${{ runner.temp }}/blocked-run-assets"),
        ("github-token", "${{ github.token }}"),
        ("repository", "${{ github.repository }}"),
        ("run-id", "${{ steps.candidate_gate.outputs.blocked_run_id }}"),
    ):
        require_yaml_scalar(
            blocked_download_with[key], expected, source, f"{build_path}.steps[6].with.{key}"
        )
    step8 = yaml_mapping(build_steps[8], source, f"{build_path}.steps[8]")
    if exact_string_mapping(step8["env"], source, f"{build_path}.steps[8].env") != (
        ("CPA_COMPAT_VERIFY_REMOTE", "1"),
    ):
        raise ContractError("formal release gates must keep remote CPA verification enabled")
    step10 = yaml_mapping(build_steps[10], source, f"{build_path}.steps[10]")
    if exact_string_mapping(step10["env"], source, f"{build_path}.steps[10].env") != (
        ("FORMAL_WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    ):
        raise ContractError("formal release provenance binding env changed")
    upload = yaml_mapping(build_steps[11], source, f"{build_path}.steps[11]")
    upload_with = require_yaml_keys(
        upload["with"],
        ("name", "path", "if-no-files-found"),
        source,
        f"{build_path}.steps[11].with",
    )
    require_yaml_scalar(
        upload_with["name"],
        "cyber-abuse-guard-v0.15-release",
        source,
        f"{build_path}.steps[11].with.name",
    )
    upload_paths = yaml_scalar(upload_with["path"], source, f"{build_path}.steps[11].with.path")
    if tuple(line.strip() for line in upload_paths.splitlines() if line.strip()) != FORMAL_RELEASE_ARTIFACTS:
        raise ContractError("formal release artifact transfer allowlist changed")
    require_yaml_scalar(
        upload_with["if-no-files-found"],
        "error",
        source,
        f"{build_path}.steps[11].with.if-no-files-found",
    )

    publish_path = "jobs.publish"
    publish = require_yaml_keys(
        jobs["publish"],
        ("needs", "environment", "permissions", "runs-on", "timeout-minutes", "steps"),
        source,
        publish_path,
    )
    require_yaml_scalar(publish["needs"], "build-and-verify", source, f"{publish_path}.needs")
    require_yaml_scalar(publish["environment"], "formal-release", source, f"{publish_path}.environment")
    publish_permissions = require_yaml_keys(
        publish["permissions"], ("actions", "contents"), source, f"{publish_path}.permissions"
    )
    require_yaml_scalar(
        publish_permissions["actions"], "read", source, f"{publish_path}.permissions.actions"
    )
    require_yaml_scalar(
        publish_permissions["contents"], "write", source, f"{publish_path}.permissions.contents"
    )
    require_yaml_scalar(publish["runs-on"], "ubuntu-24.04", source, f"{publish_path}.runs-on")
    require_yaml_scalar(
        publish["timeout-minutes"],
        "15",
        source,
        f"{publish_path}.timeout-minutes",
        tag="tag:yaml.org,2002:int",
    )
    publish_steps = yaml_sequence(publish["steps"], source, f"{publish_path}.steps")
    publish_contracts = (
        (
            "Download exact verified release artifact",
            ("name", "uses", "with"),
            "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        ),
        ("Reverify transferred filenames and checksums", ("name", "env", "run"), None),
        (
            "Recheck the release commit is still the exact main tip",
            ("name", "env", "run"),
            None,
        ),
        (
            "Create draft v0.15 GitHub release",
            ("name", "uses", "with"),
            "softprops/action-gh-release@718ea10b132b3b2eba29c1007bb80653f286566b",
        ),
    )
    if len(publish_steps) != len(publish_contracts):
        raise ContractError("formal release publish job must contain exactly four reviewed steps")
    for index, (step_node, contract) in enumerate(zip(publish_steps, publish_contracts)):
        name, keys, action = contract
        path = f"{publish_path}.steps[{index}]"
        step = require_yaml_keys(step_node, keys, source, path)
        require_yaml_scalar(step["name"], name, source, f"{path}.name")
        if action is not None:
            require_yaml_scalar(step["uses"], action, source, f"{path}.uses")
        expected_hash = FORMAL_RELEASE_STEP_RUN_SHA256.get(("publish", index))
        if expected_hash is not None:
            validate_run_hash(step, expected_hash, source, path)
    download = yaml_mapping(publish_steps[0], source, f"{publish_path}.steps[0]")
    download_with = require_yaml_keys(
        download["with"], ("name", "path"), source, f"{publish_path}.steps[0].with"
    )
    require_yaml_scalar(
        download_with["name"], "cyber-abuse-guard-v0.15-release", source, f"{publish_path}.steps[0].with.name"
    )
    require_yaml_scalar(download_with["path"], "dist", source, f"{publish_path}.steps[0].with.path")
    verifier = yaml_mapping(publish_steps[1], source, f"{publish_path}.steps[1]")
    expected_verifier_env = (
        ("BASH_ENV", ""),
        ("ENV", ""),
        ("PATH", "/usr/bin:/bin"),
        ("LC_ALL", "C"),
        ("LANG", "C"),
        ("CDPATH", ""),
        ("GLOBIGNORE", ""),
        ("PROMPT_COMMAND", ""),
        ("LD_PRELOAD", ""),
        ("LD_LIBRARY_PATH", ""),
        ("LD_AUDIT", ""),
        ("PYTHONPATH", ""),
        ("PYTHONHOME", ""),
        ("PERL5OPT", ""),
        ("RUBYOPT", ""),
        ("NODE_OPTIONS", ""),
        ("NODE_PATH", ""),
    )
    if exact_string_mapping(
        verifier["env"], source, f"{publish_path}.steps[1].env"
    ) != expected_verifier_env:
        raise ContractError("formal release publish verifier environment changed")
    main_tip = yaml_mapping(publish_steps[2], source, f"{publish_path}.steps[2]")
    if exact_string_mapping(
        main_tip["env"], source, f"{publish_path}.steps[2].env"
    ) != (("GH_TOKEN", "${{ github.token }}"),):
        raise ContractError("formal release main-tip recheck environment changed")
    release = yaml_mapping(publish_steps[3], source, f"{publish_path}.steps[3]")
    release_with = require_yaml_keys(
        release["with"],
        (
            "tag_name",
            "name",
            "draft",
            "prerelease",
            "make_latest",
            "fail_on_unmatched_files",
            "body_path",
            "files",
        ),
        source,
        f"{publish_path}.steps[3].with",
    )
    for key, expected in (("tag_name", "v0.15"), ("name", "v0.15"), ("body_path", "dist/release-evidence-final.md")):
        require_yaml_scalar(release_with[key], expected, source, f"{publish_path}.steps[3].with.{key}")
    for key, expected in (("draft", "true"), ("prerelease", "false"), ("make_latest", "false"), ("fail_on_unmatched_files", "true")):
        require_yaml_scalar(
            release_with[key],
            expected,
            source,
            f"{publish_path}.steps[3].with.{key}",
            tag="tag:yaml.org,2002:bool",
        )
    release_files = yaml_scalar(release_with["files"], source, f"{publish_path}.steps[3].with.files")
    if tuple(line.strip() for line in release_files.splitlines() if line.strip()) != FORMAL_RELEASE_ARTIFACTS:
        raise ContractError("draft release file allowlist differs from verified transfer")
    if any(
        yaml_scalar(yaml_mapping(step, source, f"{publish_path}.steps[{index}]").get("uses"), source, f"{publish_path}.steps[{index}].uses").startswith("actions/checkout@")
        for index, step in enumerate(publish_steps)
        if "uses" in yaml_mapping(step, source, f"{publish_path}.steps[{index}]")
    ):
        raise ContractError("contents:write publish job must never checkout repository source")
    if len(re.findall(r"(?m)^\s+contents:\s*write\s*$", text)) != 1:
        raise ContractError("formal release contents:write must be isolated to publish")


def validate_release_promote_workflow(text: str, source: Path) -> None:
    document = parse_workflow_yaml(text, source)
    root = require_yaml_keys(
        document,
        ("name", "on", "permissions", "concurrency", "jobs"),
        source,
        "workflow",
    )
    require_yaml_scalar(root["name"], "Promote verified v0.15 release", source, "name")
    on = require_yaml_keys(root["on"], ("workflow_dispatch",), source, "on")
    dispatch = require_yaml_keys(on["workflow_dispatch"], ("inputs",), source, "on.workflow_dispatch")
    inputs = require_yaml_keys(
        dispatch["inputs"],
        ("expected_commit", "expected_tree", "authorize_promotion"),
        source,
        "on.workflow_dispatch.inputs",
    )
    for name, node in inputs.items():
        path = f"on.workflow_dispatch.inputs.{name}"
        keys = (
            ("description", "required", "type", "default")
            if name == "authorize_promotion"
            else ("description", "required", "type")
        )
        values = require_yaml_keys(node, keys, source, path)
        yaml_scalar(values["description"], source, f"{path}.description")
        require_yaml_scalar(
            values["required"], "true", source, f"{path}.required", tag="tag:yaml.org,2002:bool"
        )
        if name == "authorize_promotion":
            require_yaml_scalar(values["type"], "boolean", source, f"{path}.type")
            require_yaml_scalar(
                values["default"], "false", source, f"{path}.default", tag="tag:yaml.org,2002:bool"
            )
        else:
            require_yaml_scalar(values["type"], "string", source, f"{path}.type")
    permissions = require_yaml_keys(root["permissions"], ("contents",), source, "permissions")
    require_yaml_scalar(permissions["contents"], "read", source, "permissions.contents")
    concurrency = require_yaml_keys(
        root["concurrency"], ("group", "cancel-in-progress"), source, "concurrency"
    )
    require_yaml_scalar(concurrency["group"], "promote-v0.15", source, "concurrency.group")
    require_yaml_scalar(
        concurrency["cancel-in-progress"],
        "false",
        source,
        "concurrency.cancel-in-progress",
        tag="tag:yaml.org,2002:bool",
    )
    jobs = require_yaml_keys(root["jobs"], ("verify", "promote"), source, "jobs")
    verify = require_yaml_keys(
        jobs["verify"],
        ("permissions", "runs-on", "timeout-minutes", "outputs", "steps"),
        source,
        "jobs.verify",
    )
    verify_permissions = require_yaml_keys(
        verify["permissions"], ("actions", "contents"), source, "jobs.verify.permissions"
    )
    require_yaml_scalar(verify_permissions["actions"], "read", source, "jobs.verify.permissions.actions")
    require_yaml_scalar(verify_permissions["contents"], "read", source, "jobs.verify.permissions.contents")
    require_yaml_scalar(verify["runs-on"], "ubuntu-24.04", source, "jobs.verify.runs-on")
    require_yaml_scalar(
        verify["timeout-minutes"], "10", source, "jobs.verify.timeout-minutes", tag="tag:yaml.org,2002:int"
    )
    outputs = require_yaml_keys(
        verify["outputs"],
        ("release_id", "asset_fingerprint", "metadata_fingerprint", "formal_run_id"),
        source,
        "jobs.verify.outputs",
    )
    require_yaml_scalar(
        outputs["release_id"], "${{ steps.verify.outputs.release_id }}", source, "jobs.verify.outputs.release_id"
    )
    require_yaml_scalar(
        outputs["asset_fingerprint"],
        "${{ steps.verify.outputs.asset_fingerprint }}",
        source,
        "jobs.verify.outputs.asset_fingerprint",
    )
    require_yaml_scalar(
        outputs["metadata_fingerprint"],
        "${{ steps.verify.outputs.metadata_fingerprint }}",
        source,
        "jobs.verify.outputs.metadata_fingerprint",
    )
    require_yaml_scalar(
        outputs["formal_run_id"],
        "${{ steps.verify.outputs.formal_run_id }}",
        source,
        "jobs.verify.outputs.formal_run_id",
    )
    verify_steps = yaml_sequence(verify["steps"], source, "jobs.verify.steps")
    if len(verify_steps) != 3:
        raise ContractError("release promotion verify job must contain exactly three reviewed steps")
    verify_step = require_yaml_keys(
        verify_steps[0], ("name", "id", "env", "run"), source, "jobs.verify.steps[0]"
    )
    require_yaml_scalar(
        verify_step["name"],
        "Verify immutable draft, provenance, and release assets",
        source,
        "jobs.verify.steps[0].name",
    )
    require_yaml_scalar(verify_step["id"], "verify", source, "jobs.verify.steps[0].id")
    expected_verify_env = (
        ("GH_TOKEN", "${{ github.token }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("AUTHORIZED", "${{ inputs.authorize_promotion }}"),
        ("DISPATCH_REF", "${{ github.ref }}"),
        ("DISPATCH_SHA", "${{ github.sha }}"),
        ("WORKFLOW_REF", "${{ github.workflow_ref }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    )
    if exact_string_mapping(verify_step["env"], source, "jobs.verify.steps[0].env") != expected_verify_env:
        raise ContractError("release promotion verify environment changed")
    validate_run_hash(
        verify_step,
        PROMOTE_STEP_RUN_SHA256[("verify", 0)],
        source,
        "jobs.verify.steps[0]",
    )
    formal_download = require_yaml_keys(
        verify_steps[1],
        ("name", "uses", "with"),
        source,
        "jobs.verify.steps[1]",
    )
    require_yaml_scalar(
        formal_download["name"],
        "Download the exact formal workflow artifact",
        source,
        "jobs.verify.steps[1].name",
    )
    require_yaml_scalar(
        formal_download["uses"],
        "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        source,
        "jobs.verify.steps[1].uses",
    )
    formal_download_with = require_yaml_keys(
        formal_download["with"],
        ("name", "path", "github-token", "repository", "run-id"),
        source,
        "jobs.verify.steps[1].with",
    )
    for key, expected in (
        ("name", "cyber-abuse-guard-v0.15-release"),
        ("path", "${{ runner.temp }}/formal-run-assets"),
        ("github-token", "${{ github.token }}"),
        ("repository", "${{ github.repository }}"),
        ("run-id", "${{ steps.verify.outputs.formal_run_id }}"),
    ):
        require_yaml_scalar(
            formal_download_with[key], expected, source, f"jobs.verify.steps[1].with.{key}"
        )
    formal_compare = require_yaml_keys(
        verify_steps[2], ("name", "run"), source, "jobs.verify.steps[2]"
    )
    require_yaml_scalar(
        formal_compare["name"],
        "Prove every draft asset is byte-identical to the formal workflow artifact",
        source,
        "jobs.verify.steps[2].name",
    )
    validate_run_hash(
        formal_compare,
        PROMOTE_STEP_RUN_SHA256[("verify", 2)],
        source,
        "jobs.verify.steps[2]",
    )

    promote = require_yaml_keys(
        jobs["promote"],
        ("needs", "environment", "permissions", "runs-on", "timeout-minutes", "steps"),
        source,
        "jobs.promote",
    )
    require_yaml_scalar(promote["needs"], "verify", source, "jobs.promote.needs")
    require_yaml_scalar(
        promote["environment"], "formal-release-promotion", source, "jobs.promote.environment"
    )
    promote_permissions = require_yaml_keys(
        promote["permissions"], ("contents",), source, "jobs.promote.permissions"
    )
    require_yaml_scalar(
        promote_permissions["contents"], "write", source, "jobs.promote.permissions.contents"
    )
    require_yaml_scalar(promote["runs-on"], "ubuntu-24.04", source, "jobs.promote.runs-on")
    require_yaml_scalar(
        promote["timeout-minutes"], "5", source, "jobs.promote.timeout-minutes", tag="tag:yaml.org,2002:int"
    )
    promote_steps = yaml_sequence(promote["steps"], source, "jobs.promote.steps")
    if len(promote_steps) != 1:
        raise ContractError("release promotion write job must contain exactly one reviewed step")
    promote_step = require_yaml_keys(
        promote_steps[0], ("name", "env", "run"), source, "jobs.promote.steps[0]"
    )
    require_yaml_scalar(
        promote_step["name"],
        "Reverify immutable asset set and publish the same draft",
        source,
        "jobs.promote.steps[0].name",
    )
    expected_promote_env = (
        ("GH_TOKEN", "${{ github.token }}"),
        ("RELEASE_ID", "${{ needs.verify.outputs.release_id }}"),
        ("EXPECTED_ASSET_FINGERPRINT", "${{ needs.verify.outputs.asset_fingerprint }}"),
        ("EXPECTED_METADATA_FINGERPRINT", "${{ needs.verify.outputs.metadata_fingerprint }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
    )
    if exact_string_mapping(promote_step["env"], source, "jobs.promote.steps[0].env") != expected_promote_env:
        raise ContractError("release promotion write environment changed")
    validate_run_hash(
        promote_step,
        PROMOTE_STEP_RUN_SHA256[("promote", 0)],
        source,
        "jobs.promote.steps[0]",
    )
    if re.search(r"(?i)actions/checkout@|(?:^|[\s;&|])(?:\./)?scripts/", text):
        raise ContractError("release promotion must remain no-checkout and script-free")
    if len(re.findall(r"(?m)^\s+contents:\s*write\s*$", text)) != 1:
        raise ContractError("release promotion contents:write must be isolated to promote")


def validate_blocked_prerelease_structure(
    document: MappingNode, source: Path
) -> dict[str, list[Node]]:
    root = require_yaml_keys(document, BLOCKED_TOP_LEVEL_KEYS, source, "workflow")
    require_yaml_scalar(root["name"], BLOCKED_PRERELEASE_MARKER, source, "name")

    if yaml_mapping_keys(root["on"], source, "on") != ("workflow_dispatch",):
        raise ContractError("blocked prerelease must remain manual-only workflow_dispatch")
    on = yaml_mapping(root["on"], source, "on")
    dispatch = require_yaml_keys(
        on["workflow_dispatch"], ("inputs",), source, "on.workflow_dispatch"
    )
    inputs = require_yaml_keys(
        dispatch["inputs"],
        BLOCKED_PRERELEASE_INPUT_ORDER,
        source,
        "on.workflow_dispatch.inputs",
    )
    for input_name, input_node in inputs.items():
        path = f"on.workflow_dispatch.inputs.{input_name}"
        if input_name == "authorize_blocked_prerelease":
            expected_keys = ("description", "required", "type", "default")
        else:
            expected_keys = ("description", "required", "type")
        values = require_yaml_keys(input_node, expected_keys, source, path)
        yaml_scalar(values["description"], source, f"{path}.description")
        require_yaml_scalar(
            values["required"],
            "true",
            source,
            f"{path}.required",
            tag="tag:yaml.org,2002:bool",
        )
        if input_name == "authorize_blocked_prerelease":
            require_yaml_scalar(values["type"], "boolean", source, f"{path}.type")
            require_yaml_scalar(
                values["default"],
                "false",
                source,
                f"{path}.default",
                tag="tag:yaml.org,2002:bool",
            )
        else:
            require_yaml_scalar(values["type"], "string", source, f"{path}.type")

    permission_keys = yaml_mapping_keys(root["permissions"], source, "permissions")
    if "actions" not in permission_keys:
        raise ContractError("blocked prerelease must grant top-level actions: read")
    permissions = require_yaml_keys(
        root["permissions"], ("actions", "contents"), source, "permissions"
    )
    require_yaml_scalar(permissions["actions"], "read", source, "permissions.actions")
    require_yaml_scalar(permissions["contents"], "read", source, "permissions.contents")
    concurrency = require_yaml_keys(
        root["concurrency"], ("group", "cancel-in-progress"), source, "concurrency"
    )
    require_yaml_scalar(
        concurrency["group"],
        "round6-blocked-prerelease-${{ inputs.tag }}",
        source,
        "concurrency.group",
    )
    require_yaml_scalar(
        concurrency["cancel-in-progress"],
        "false",
        source,
        "concurrency.cancel-in-progress",
        tag="tag:yaml.org,2002:bool",
    )
    env = require_yaml_keys(
        root["env"],
        ("GO_VERSION", "VERSION", "CYCLONEDX_GOMOD_VERSION"),
        source,
        "env",
    )
    for env_name in ("GO_VERSION", "VERSION", "CYCLONEDX_GOMOD_VERSION"):
        require_yaml_scalar(
            env[env_name], SAFE_WORKFLOW_ENV[env_name], source, f"env.{env_name}"
        )

    jobs = require_yaml_keys(
        root["jobs"], ("admission", "verify", "publish"), source, "jobs"
    )
    steps_by_job: dict[str, list[Node]] = {}
    expected_timeouts = {"admission": "5", "verify": "60", "publish": "10"}
    for job_name in ("admission", "verify", "publish"):
        job_path = f"jobs.{job_name}"
        if job_name == "publish" and "environment" not in yaml_mapping(
            jobs[job_name], source, job_path
        ):
            raise ContractError(
                "publish job must use the round6-independent-audit protected environment"
            )
        job = require_yaml_keys(
            jobs[job_name], BLOCKED_JOB_KEYS[job_name], source, job_path
        )
        require_yaml_scalar(
            job["runs-on"], "ubuntu-24.04", source, f"{job_path}.runs-on"
        )
        require_yaml_scalar(
            job["timeout-minutes"],
            expected_timeouts[job_name],
            source,
            f"{job_path}.timeout-minutes",
            tag="tag:yaml.org,2002:int",
        )
        if job_name == "verify":
            require_yaml_scalar(job["needs"], "admission", source, f"{job_path}.needs")
            verify_permissions = require_yaml_keys(
                job["permissions"],
                ("actions", "contents"),
                source,
                f"{job_path}.permissions",
            )
            require_yaml_scalar(
                verify_permissions["actions"],
                "read",
                source,
                f"{job_path}.permissions.actions",
            )
            require_yaml_scalar(
                verify_permissions["contents"],
                "read",
                source,
                f"{job_path}.permissions.contents",
            )
        elif job_name == "publish":
            require_yaml_scalar(job["needs"], "verify", source, f"{job_path}.needs")
            require_yaml_scalar(
                job["environment"],
                "round6-independent-audit",
                source,
                f"{job_path}.environment",
            )
            expected_publish_if = (
                "fromJSON(inputs.external_attestations_json).host_validation == 'PASS' && "
                "fromJSON(inputs.external_attestations_json).independent_audit_validation == 'PASS' && "
                "fromJSON(inputs.external_attestations_json).independent_evaluation_validation == 'PASS' && "
                "inputs.authorize_blocked_prerelease == true"
            )
            if yaml_scalar(job["if"], source, f"{job_path}.if") != expected_publish_if:
                raise ContractError(
                    "publish job is missing explicit gate: exact reviewed if expression"
                )
            publish_permissions = require_yaml_keys(
                job["permissions"],
                ("actions", "contents"),
                source,
                f"{job_path}.permissions",
            )
            require_yaml_scalar(
                publish_permissions["actions"],
                "read",
                source,
                f"{job_path}.permissions.actions",
            )
            require_yaml_scalar(
                publish_permissions["contents"],
                "write",
                source,
                f"{job_path}.permissions.contents",
            )

        steps = yaml_sequence(job["steps"], source, f"{job_path}.steps")
        contracts = BLOCKED_STEP_CONTRACTS[job_name]
        if len(steps) != len(contracts):
            count_words = {2: "two", 3: "three", 4: "four", 14: "fourteen"}
            raise ContractError(
                f"blocked prerelease {job_name} job must contain exactly "
                f"{count_words.get(len(contracts), str(len(contracts)))} reviewed steps"
            )
        for index, (step_node, (expected_name, expected_keys, expected_action)) in enumerate(
            zip(steps, contracts)
        ):
            step_path = f"{job_path}.steps[{index}]"
            step = require_yaml_keys(step_node, expected_keys, source, step_path)
            require_yaml_scalar(step["name"], expected_name, source, f"{step_path}.name")
            if expected_action is not None:
                require_yaml_scalar(
                    step["uses"], expected_action, source, f"{step_path}.uses"
                )
            contract_key = (job_name, index)
            if "run" in step:
                run_node = step["run"]
                run_text = yaml_scalar(run_node, source, f"{step_path}.run")
                expected_hash = BLOCKED_STEP_RUN_SHA256.get(contract_key)
                if (
                    expected_hash is None
                    or run_node.tag != "tag:yaml.org,2002:str"
                    or run_node.style != BLOCKED_STEP_RUN_STYLE[contract_key]
                    or hashlib.sha256(run_text.encode("utf-8")).hexdigest()
                    != expected_hash
                ):
                    raise ContractError(
                        f"blocked prerelease {step_path} run must match the exact reviewed text"
                    )
            elif contract_key in BLOCKED_STEP_RUN_SHA256:
                raise ContractError(f"blocked prerelease {step_path} is missing reviewed run")
            if "env" in step:
                env_path = f"{step_path}.env"
                env_node = step["env"]
                if not isinstance(env_node, MappingNode):
                    raise ContractError(f"blocked prerelease {env_path} must be a mapping")
                actual_env = tuple(
                    (
                        key_node.value,
                        yaml_scalar(value_node, source, f"{env_path}.{key_node.value}"),
                    )
                    for key_node, value_node in env_node.value
                )
                if any(
                    value_node.tag != "tag:yaml.org,2002:str"
                    for _, value_node in env_node.value
                ) or actual_env != BLOCKED_STEP_ENV.get(contract_key):
                    raise ContractError(
                        f"blocked prerelease {env_path} must match the exact reviewed mapping"
                    )
            elif contract_key in BLOCKED_STEP_ENV:
                raise ContractError(f"blocked prerelease {step_path} is missing reviewed env")
            if "with" in step:
                yaml_mapping(step["with"], source, f"{step_path}.with")
        steps_by_job[job_name] = steps

    checkout = yaml_mapping(steps_by_job["verify"][0], source, "jobs.verify.steps[0]")
    checkout_with = require_yaml_keys(
        checkout["with"],
        (
            "ref",
            "fetch-depth",
            "persist-credentials",
            "filter",
            "sparse-checkout-cone-mode",
            "sparse-checkout",
        ),
        source,
        "jobs.verify.steps[0].with",
    )
    require_yaml_scalar(
        checkout_with["ref"],
        "${{ inputs.tag }}",
        source,
        "jobs.verify.steps[0].with.ref",
    )
    require_yaml_scalar(
        checkout_with["fetch-depth"],
        "0",
        source,
        "jobs.verify.steps[0].with.fetch-depth",
        tag="tag:yaml.org,2002:int",
    )
    persist_credentials = checkout_with["persist-credentials"]
    if not (
        isinstance(persist_credentials, ScalarNode)
        and persist_credentials.value == "false"
        and persist_credentials.tag == "tag:yaml.org,2002:bool"
    ):
        raise ContractError("blocked prerelease checkout must disable persisted credentials")
    require_yaml_scalar(
        checkout_with["filter"],
        "blob:none",
        source,
        "jobs.verify.steps[0].with.filter",
    )
    require_yaml_scalar(
        checkout_with["sparse-checkout-cone-mode"],
        "false",
        source,
        "jobs.verify.steps[0].with.sparse-checkout-cone-mode",
        tag="tag:yaml.org,2002:bool",
    )
    sparse = yaml_scalar(
        checkout_with["sparse-checkout"],
        source,
        "jobs.verify.steps[0].with.sparse-checkout",
    )
    if tuple(line.strip() for line in sparse.splitlines() if line.strip()) != ROUND6_SPARSE_PATTERNS:
        raise ContractError("blocked prerelease checkout sparse boundary changed")

    setup_go = yaml_mapping(steps_by_job["verify"][3], source, "jobs.verify.steps[3]")
    setup_go_with = require_yaml_keys(
        setup_go["with"],
        ("go-version", "cache"),
        source,
        "jobs.verify.steps[3].with",
    )
    require_yaml_scalar(
        setup_go_with["go-version"],
        "${{ env.GO_VERSION }}",
        source,
        "jobs.verify.steps[3].with.go-version",
    )
    require_yaml_scalar(
        setup_go_with["cache"],
        "true",
        source,
        "jobs.verify.steps[3].with.cache",
        tag="tag:yaml.org,2002:bool",
    )

    candidate_download = yaml_mapping(
        steps_by_job["verify"][5], source, "jobs.verify.steps[5]"
    )
    candidate_download_with = require_yaml_keys(
        candidate_download["with"],
        ("name", "path", "github-token", "repository", "run-id"),
        source,
        "jobs.verify.steps[5].with",
    )
    for key, expected in (
        ("name", "round6-v0.15-candidate-${{ inputs.expected_commit }}"),
        ("path", "${{ runner.temp }}/host-tested-candidate"),
        ("github-token", "${{ github.token }}"),
        ("repository", "${{ github.repository }}"),
        ("run-id", "${{ inputs.candidate_run_id }}"),
    ):
        require_yaml_scalar(
            candidate_download_with[key],
            expected,
            source,
            f"jobs.verify.steps[5].with.{key}",
        )

    upload = yaml_mapping(steps_by_job["verify"][13], source, "jobs.verify.steps[13]")
    upload_with = require_yaml_keys(
        upload["with"],
        ("name", "path", "if-no-files-found", "retention-days"),
        source,
        "jobs.verify.steps[13].with",
    )
    require_yaml_scalar(
        upload_with["name"],
        "round6-blocked-${{ inputs.expected_commit }}",
        source,
        "jobs.verify.steps[13].with.name",
    )
    expected_artifacts = (
        "dist/cyber-abuse-guard-v0.15.so",
        "dist/cyber-abuse-guard-v0.15.so.sha256",
        "dist/cyber-abuse-guard_0.15_linux_amd64.zip",
        "dist/build-metadata.json",
        "dist/checksums.txt",
        "dist/ruleset-manifest.json",
        "dist/ruleset.sha256",
        "dist/sbom.cdx.json",
    )
    upload_paths = yaml_scalar(
        upload_with["path"], source, "jobs.verify.steps[13].with.path"
    )
    if tuple(line.strip() for line in upload_paths.splitlines() if line.strip()) != expected_artifacts:
        raise ContractError("blocked prerelease artifact transfer allowlist changed")
    require_yaml_scalar(
        upload_with["if-no-files-found"],
        "error",
        source,
        "jobs.verify.steps[13].with.if-no-files-found",
    )
    require_yaml_scalar(
        upload_with["retention-days"],
        "1",
        source,
        "jobs.verify.steps[13].with.retention-days",
        tag="tag:yaml.org,2002:int",
    )

    download = yaml_mapping(steps_by_job["publish"][0], source, "jobs.publish.steps[0]")
    download_with = require_yaml_keys(
        download["with"],
        ("name", "path"),
        source,
        "jobs.publish.steps[0].with",
    )
    require_yaml_scalar(
        download_with["name"],
        "round6-blocked-${{ inputs.expected_commit }}",
        source,
        "jobs.publish.steps[0].with.name",
    )
    require_yaml_scalar(
        download_with["path"], "dist", source, "jobs.publish.steps[0].with.path"
    )
    attested_upload = yaml_mapping(
        steps_by_job["publish"][2], source, "jobs.publish.steps[2]"
    )
    attested_upload_with = require_yaml_keys(
        attested_upload["with"],
        ("name", "path", "if-no-files-found", "retention-days"),
        source,
        "jobs.publish.steps[2].with",
    )
    require_yaml_scalar(
        attested_upload_with["name"],
        "round6-blocked-attested-${{ inputs.expected_commit }}",
        source,
        "jobs.publish.steps[2].with.name",
    )
    expected_attested_artifacts = expected_artifacts + (
        "dist/round6-prerelease-attestation.json",
        "dist/round6-prerelease-attestation.json.sha256",
    )
    attested_paths = yaml_scalar(
        attested_upload_with["path"], source, "jobs.publish.steps[2].with.path"
    )
    if tuple(
        line.strip() for line in attested_paths.splitlines() if line.strip()
    ) != expected_attested_artifacts:
        raise ContractError("blocked prerelease attested artifact allowlist changed")
    require_yaml_scalar(
        attested_upload_with["if-no-files-found"],
        "error",
        source,
        "jobs.publish.steps[2].with.if-no-files-found",
    )
    require_yaml_scalar(
        attested_upload_with["retention-days"],
        "30",
        source,
        "jobs.publish.steps[2].with.retention-days",
        tag="tag:yaml.org,2002:int",
    )
    return steps_by_job


def shell_command_segments(command: str) -> tuple[list[str], ...]:
    tokens = shell_tokens(command)
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in SHELL_OPERATORS:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return tuple(segments)


HEREDOC = re.compile(
    r"(?<!<)<<(?P<strip_tabs>-?)(?!<)\s*"
    r"(?P<delimiter>'[^'\r\n]+'|\"[^\"\r\n]+\"|[A-Za-z0-9_.-]+)"
)


def mutation_shell_commands(
    text: str, source: Path = Path("<workflow>")
) -> tuple[str, ...]:
    commands: list[str] = []
    pending = ""
    join_continuation = False
    heredocs: list[tuple[str, bool]] = []
    in_array = False
    array_state = (False, False)
    command_state = SHELL_NEUTRAL_STATE
    array_start = re.compile(
        r"^(?:(?:local|readonly|declare)(?:\s+-[aA])?\s+)?"
        r"[A-Za-z_][A-Za-z0-9_]*\+?=\("
    )
    for raw in text.splitlines():
        if heredocs:
            delimiter, strip_tabs = heredocs[0]
            candidate = raw.lstrip("\t") if strip_tabs else raw
            if candidate == delimiter:
                heredocs.pop(0)
                if not heredocs and shell_state_neutral(command_state) and pending:
                    shell_tokens(pending)
                    commands.append(pending)
                    pending = ""
            continue

        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or (
            stripped.startswith("#") and shell_state_neutral(command_state)
        ):
            continue
        if in_array:
            array_state = scan_shell_array_fragment(stripped, source, array_state)
            if array_state == (False, False) and re.fullmatch(
                r"\)\s*;?(?:\s+#.*)?", stripped
            ):
                in_array = False
            continue
        if (
            shell_state_neutral(command_state)
            and not pending
            and array_start.match(stripped)
        ):
            array_state = scan_shell_array_fragment(stripped, source, (False, False))
            if array_state != (False, False) or not re.search(
                r"\)\s*;?(?:\s+#.*)?$", stripped
            ):
                in_array = True
            continue

        if not pending:
            line = line.lstrip()
        line, command_state, continued = shell_line_continuation(line, command_state)
        if not line:
            continue
        if continued:
            line = line[:-1]
        if pending:
            pending += ("" if join_continuation else "\n") + line
        else:
            pending = line
        join_continuation = continued
        for match in HEREDOC.finditer(line):
            delimiter = match.group("delimiter")
            if delimiter[:1] in {"'", '"'}:
                delimiter = delimiter[1:-1]
            heredocs.append((delimiter, match.group("strip_tabs") == "-"))
        if continued or heredocs or not shell_state_neutral(command_state):
            continue

        shell_tokens(pending)
        commands.append(pending)
        pending = ""
        join_continuation = False

    if pending or heredocs or in_array or not shell_state_neutral(command_state):
        raise ContractError("unterminated shell construct in blocked prerelease workflow")
    return tuple(commands)


def unwrap_shell_command(segment: list[str]) -> tuple[str, list[str]] | None:
    cursor = 0
    while cursor < len(segment) and (
        ASSIGNMENT.match(segment[cursor])
        or segment[cursor] in {"if", "then", "while", "until", "do", "!"}
    ):
        cursor += 1
    while cursor < len(segment):
        wrapper = Path(segment[cursor]).name
        if wrapper == "command":
            cursor += 1
            while cursor < len(segment) and segment[cursor].startswith("-"):
                cursor += 1
            continue
        if wrapper == "env":
            cursor += 1
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                if token in {"-S", "--split-string"}:
                    if cursor + 1 >= len(segment):
                        raise ContractError("env split-string option lacks its command string")
                    try:
                        expanded = shlex.split(segment[cursor + 1], posix=True)
                    except ValueError as exc:
                        raise ContractError(
                            "cannot parse env split-string command safely"
                        ) from exc
                    return unwrap_shell_command(expanded + segment[cursor + 2 :])
                if token.startswith("--split-string=") or (
                    token.startswith("-S") and token != "-S"
                ):
                    value = token.split("=", 1)[1] if "=" in token else token[2:]
                    try:
                        expanded = shlex.split(value, posix=True)
                    except ValueError as exc:
                        raise ContractError(
                            "cannot parse env split-string command safely"
                        ) from exc
                    return unwrap_shell_command(expanded + segment[cursor + 1 :])
                if token in {"-u", "--unset", "-C", "--chdir"}:
                    cursor += 2
                    continue
                if token.startswith(("--unset=", "--chdir=")):
                    cursor += 1
                    continue
                if token in {"-i", "--ignore-environment"} or ASSIGNMENT.match(token):
                    cursor += 1
                    continue
                if token.startswith("-"):
                    cursor += 1
                    continue
                break
            continue
        if wrapper == "time":
            cursor += 1
            value_options = {"-f", "--format", "-o", "--output"}
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                option_name = token.split("=", 1)[0]
                if option_name in value_options:
                    cursor += 1 if "=" in token else 2
                    continue
                if token.startswith(("-f", "-o")) and len(token) > 2:
                    cursor += 1
                    continue
                if token.startswith("-"):
                    cursor += 1
                    continue
                break
            continue
        if wrapper == "timeout":
            cursor += 1
            value_options = {"-k", "--kill-after", "-s", "--signal"}
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                option_name = token.split("=", 1)[0]
                if option_name in value_options:
                    cursor += 1 if "=" in token else 2
                    continue
                if token.startswith(("-k", "-s")) and len(token) > 2:
                    cursor += 1
                    continue
                if token.startswith("-"):
                    cursor += 1
                    continue
                break
            if cursor >= len(segment):
                return None
            cursor += 1
            continue
        if wrapper == "nice":
            cursor += 1
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                option_name = token.split("=", 1)[0]
                if option_name in {"-n", "--adjustment"}:
                    cursor += 1 if "=" in token else 2
                    continue
                if token.startswith("-n") and len(token) > 2:
                    cursor += 1
                    continue
                if re.fullmatch(r"-\d+", token) or token.startswith("--"):
                    cursor += 1
                    continue
                break
            continue
        if wrapper == "nohup":
            cursor += 1
            while cursor < len(segment) and segment[cursor].startswith("-"):
                if segment[cursor] == "--":
                    cursor += 1
                    break
                cursor += 1
            continue
        if wrapper == "stdbuf":
            cursor += 1
            value_options = {"-i", "--input", "-o", "--output", "-e", "--error"}
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                option_name = token.split("=", 1)[0]
                if option_name in value_options:
                    cursor += 1 if "=" in token else 2
                    continue
                if token.startswith(("-i", "-o", "-e")) and len(token) > 2:
                    cursor += 1
                    continue
                if token.startswith("-"):
                    cursor += 1
                    continue
                break
            continue
        if wrapper == "sudo":
            cursor += 1
            value_options = {
                "-u", "--user", "-g", "--group", "-h", "--host",
                "-p", "--prompt", "-C", "--close-from", "-T",
                "--command-timeout", "-R", "--chroot", "-D", "--chdir",
            }
            while cursor < len(segment):
                token = segment[cursor]
                if token == "--":
                    cursor += 1
                    break
                option_name = token.split("=", 1)[0]
                if option_name in value_options:
                    cursor += 1 if "=" in token else 2
                    continue
                if token.startswith("-"):
                    cursor += 1
                    continue
                break
            continue
        break
    if cursor >= len(segment):
        return None
    return segment[cursor], segment[cursor + 1 :]


def option_subcommand(args: list[str], value_options: set[str]) -> str | None:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        option_name = token.split("=", 1)[0]
        if option_name in value_options:
            index += 1 if "=" in token else 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return Path(token).name
    if index < len(args):
        return Path(args[index]).name
    return None


def mutating_command_reason(segment: list[str]) -> str | None:
    unwrapped = unwrap_shell_command(segment)
    if unwrapped is None:
        return None
    executable_path, args = unwrapped
    executable = Path(executable_path).name
    if executable in {"sh", "bash", "dash", "zsh"} and any(
        token == "-c"
        or (token.startswith("-") and not token.startswith("--") and "c" in token[1:])
        for token in args
    ):
        return f"{executable} dynamic command execution"
    if executable == "eval":
        return "eval dynamic command execution"
    if executable == "xargs":
        return "xargs dynamic command execution"
    if executable == "find" and any(
        token in {"-exec", "-execdir", "-ok", "-okdir"} for token in args
    ):
        return "find dynamic command execution"
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable) and any(
        token == "-c" or token.startswith("-c") for token in args
    ):
        return f"{executable} dynamic command execution"
    if executable == "node" and any(
        token in {"-e", "--eval", "-p", "--print"}
        or token.startswith(("-e", "--eval=", "-p", "--print="))
        for token in args
    ):
        return "node dynamic command execution"
    if executable == "git":
        subcommand = option_subcommand(
            args,
            {"-C", "-c", "--config-env", "--exec-path", "--git-dir", "--work-tree", "--namespace"},
        )
        if subcommand in {"push", "tag", "update-ref"}:
            return f"git {subcommand}"
    elif executable == "gh":
        subcommand = option_subcommand(
            args, {"-R", "--repo", "--hostname", "--config", "--cwd"}
        )
        if subcommand in {"api", "release"}:
            return f"gh {subcommand}"
    elif executable == "curl":
        for token in args:
            lower = token.lower()
            if lower.startswith(("--request", "--data", "--form", "--upload-file", "--json", "--config")):
                return f"curl {token}"
            if token.startswith("-") and not token.startswith("--") and any(
                option in token[1:] for option in "XdFTK"
            ):
                return f"curl {token}"
        if re.search(
            r"(?i)x-http-method-override\s*:\s*(?:post|put|patch|delete)", " ".join(args)
        ):
            return "curl method override"
    elif executable == "wget":
        for token in args:
            if token.lower().startswith(
                ("--method", "--post-data", "--post-file", "--body-data", "--body-file", "--upload-file")
            ):
                return f"wget {token}"
    return None


def validate_pre_final_mutations(
    steps_by_job: dict[str, list[Node]], source: Path
) -> None:
    for job_name in ("admission", "verify", "publish"):
        steps = steps_by_job[job_name]
        limit = len(steps) - 1 if job_name == "publish" else len(steps)
        for index, step_node in enumerate(steps[:limit]):
            path = f"jobs.{job_name}.steps[{index}]"
            step = yaml_mapping(step_node, source, path)
            run_node = step.get("run")
            if run_node is None:
                continue
            for command in mutation_shell_commands(
                yaml_scalar(run_node, source, f"{path}.run")
            ):
                for segment in shell_command_segments(command):
                    reason = mutating_command_reason(segment)
                    if reason is not None:
                        raise ContractError(
                            f"blocked prerelease forbids {reason} before final publish: {path}"
                        )


def validate_blocked_prerelease_workflow(text: str, source: Path) -> None:
    validate_workflow_safety(text, source)
    document = parse_workflow_yaml(text, source)
    validate_sensitive_workflow_expressions(
        document,
        source,
        allowed_token_paths=BLOCKED_ALLOWED_GITHUB_TOKEN_PATHS,
        allowed_identity_expressions=BLOCKED_ALLOWED_GITHUB_IDENTITY_EXPRESSIONS,
    )


    steps_by_job = validate_blocked_prerelease_structure(document, source)
    validate_pre_final_mutations(steps_by_job, source)
    if not re.search(
        rf"(?m)^name:\s*{re.escape(BLOCKED_PRERELEASE_MARKER)}\s*$", text
    ):
        raise ContractError(
            f"attested prerelease workflow name must be exactly {BLOCKED_PRERELEASE_MARKER!r}: {source}"
        )

    on_block = mapping_block(text, "on", 0)
    events = set(re.findall(r"(?m)^  ([A-Za-z0-9_-]+):", on_block))
    if events != {"workflow_dispatch"}:
        raise ContractError(
            f"blocked prerelease must be manual-only workflow_dispatch, got {sorted(events)}"
        )
    dispatch_block = mapping_block(on_block, "workflow_dispatch", 2)
    inputs_block = mapping_block(dispatch_block, "inputs", 4)
    for input_name in BLOCKED_PRERELEASE_INPUTS:
        input_block = mapping_block(inputs_block, input_name, 6)
        if not re.search(r"(?m)^        required:\s*true\s*$", input_block):
            raise ContractError(
                f"blocked prerelease input {input_name} must be explicitly required"
            )
    authorization_block = mapping_block(
        inputs_block, "authorize_blocked_prerelease", 6
    )
    if not re.search(r"(?m)^        type:\s*boolean\s*$", authorization_block) or not re.search(
        r"(?m)^        default:\s*false\s*$", authorization_block
    ):
        raise ContractError(
            "blocked prerelease authorization must be a required boolean defaulting false"
        )

    permissions = mapping_block(text, "permissions", 0)
    if not re.search(r"(?m)^  actions:\s*read\s*$", permissions):
        raise ContractError("blocked prerelease must grant top-level actions: read")
    if not re.search(r"(?m)^  contents:\s*read\s*$", permissions):
        raise ContractError("blocked prerelease top-level contents permission must remain read-only")

    if "${{ secrets." in text:
        raise ContractError("blocked prerelease may not expose repository secrets")
    if text.count("${{ github.token }}") != 4:
        raise ContractError(
            "blocked prerelease may expose github.token only to reviewed CI, candidate admission, candidate download, and final publish steps"
        )

    jobs = job_blocks(text)
    if set(jobs) != {"admission", "verify", "publish"}:
        raise ContractError(
            "blocked prerelease must define exactly admission, verify, and publish jobs"
        )
    admission = jobs["admission"]
    verify_job = jobs["verify"]
    publish_job = jobs["publish"]
    admission_steps = step_blocks(admission)
    if len(admission_steps) != 3:
        raise ContractError("blocked prerelease admission must contain exactly three reviewed steps")
    reviewed_admission = (
        (
            "Fail closed unless every external gate and authorization is explicit",
            ADMISSION_INPUT_ENV,
            ADMISSION_INPUT_COMMANDS,
        ),
        (
            "Bind admission to a successful CI run for the exact commit",
            ADMISSION_CI_ENV,
            ADMISSION_CI_COMMANDS,
        ),
        (
            "Bind admission to the successful clean-candidate run",
            CANDIDATE_ADMISSION_ENV,
            CANDIDATE_ADMISSION_COMMANDS,
        ),
    )
    for step, (name, expected_env, expected_commands) in zip(
        admission_steps, reviewed_admission
    ):
        if not re.search(rf"(?m)^\s+-\s+name:\s*{re.escape(name)}\s*$", step):
            raise ContractError("blocked prerelease admission step name/order changed")
        if re.search(r"(?m)^\s+(?:if|continue-on-error|shell):", step):
            raise ContractError("blocked prerelease admission steps must be unconditional")
        try:
            env_block = mapping_block(step, "env", 8)
        except ContractError as exc:
            raise ContractError("blocked prerelease admission step lacks exact environment") from exc
        actual_env = tuple(
            line.strip() for line in env_block.splitlines()[1:] if line.strip()
        )
        runs = yaml_run_blocks(step)
        actual_commands = (
            tuple(line.rstrip() for line in runs[0].splitlines() if line.strip())
            if len(runs) == 1
            else ()
        )
        if actual_env != expected_env or actual_commands != expected_commands:
            raise ContractError(
                "blocked prerelease admission must use the exact reviewed environment and executable command sequence"
            )

    if not re.search(r"(?m)^    needs:\s*admission\s*$", verify_job):
        raise ContractError("blocked prerelease verify job must depend on admission")
    if re.search(r"(?m)^    (?:if|environment):\s*", verify_job):
        raise ContractError("blocked prerelease verify job may not be conditional or environment-gated")
    verify_permissions = tuple(
        line.strip()
        for line in mapping_block(verify_job, "permissions", 4).splitlines()
        if line.strip()
    )
    if verify_permissions != ("permissions:", "actions: read", "contents: read"):
        raise ContractError(
            "blocked prerelease verify job must remain actions/contents read only"
        )
    if re.search(r"(?m)^\s+(?:GH_TOKEN|GITHUB_TOKEN):", verify_job):
        raise ContractError(
            "blocked prerelease verify job may pass github.token only to the exact candidate artifact download input"
        )

    verify_steps = step_blocks(verify_job)
    if len(verify_steps) < 4:
        raise ContractError("blocked prerelease verify job is missing reviewed verification steps")
    final_verify_step = verify_steps[-2]
    if not re.search(
        r"(?m)^\s+-\s+name:\s*Reverify source and artifact identity before transfer\s*$",
        final_verify_step,
    ):
        raise ContractError("blocked prerelease verify job must freeze identity before transfer")
    if re.search(r"(?m)^\s+(?:if|continue-on-error|shell):", final_verify_step):
        raise ContractError("blocked prerelease final verify identity step must be unconditional")
    upload_step = verify_steps[-1]
    if not re.search(
        r"(?m)^\s+-\s+name:\s*Upload exact verified blocked-development artifacts\s*$",
        upload_step,
    ) or not re.search(
        r"(?m)^\s+uses:\s*actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a(?:\s+#.*)?$",
        upload_step,
    ):
        raise ContractError("blocked prerelease verify job must end with the pinned artifact upload")
    expected_upload_with = """        with:
          name: round6-blocked-${{ inputs.expected_commit }}
          path: |
            dist/cyber-abuse-guard-v0.15.so
            dist/cyber-abuse-guard-v0.15.so.sha256
            dist/cyber-abuse-guard_0.15_linux_amd64.zip
            dist/build-metadata.json
            dist/checksums.txt
            dist/ruleset-manifest.json
            dist/ruleset.sha256
            dist/sbom.cdx.json
          if-no-files-found: error
          retention-days: 1"""
    if mapping_block(upload_step, "with", 8) != expected_upload_with:
        raise ContractError("blocked prerelease artifact transfer allowlist changed")

    publish_if = tuple(
        line.strip()
        for line in mapping_block(publish_job, "if", 4).splitlines()
        if line.strip()
    )
    if publish_if != BLOCKED_PRERELEASE_IF_LINES:
        raise ContractError("publish job is missing explicit gate: exact reviewed if expression")
    if not re.search(r"(?m)^    needs:\s*verify\s*$", publish_job):
        raise ContractError("publish job must depend on successful exact-source verification")
    if not re.search(
        r"(?m)^    environment:\s*round6-independent-audit\s*$", publish_job
    ):
        raise ContractError(
            "publish job must use the round6-independent-audit protected environment"
        )
    publish_permissions = tuple(
        line.strip()
        for line in mapping_block(publish_job, "permissions", 4).splitlines()
        if line.strip()
    )
    if publish_permissions != ("permissions:", "actions: read", "contents: write"):
        raise ContractError("only the fully gated publish job may receive contents: write")
    if len(re.findall(r"(?m)^\s+contents:\s*write\s*$", text)) != 1:
        raise ContractError("contents: write must appear only once in the publish job")

    publish_steps = step_blocks(publish_job)
    if len(publish_steps) != 4:
        raise ContractError("blocked prerelease publish job must contain exactly four reviewed steps")
    download_step, transfer_step, _, final_publish_step = publish_steps
    if not re.search(
        r"(?m)^\s+-\s+name:\s*Download exact verified blocked-development artifacts\s*$",
        download_step,
    ) or not re.search(
        r"(?m)^\s+uses:\s*actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131(?:\s+#.*)?$",
        download_step,
    ):
        raise ContractError("blocked prerelease publish job must use the pinned artifact download")
    expected_download_with = """        with:
          name: round6-blocked-${{ inputs.expected_commit }}
          path: dist"""
    if mapping_block(download_step, "with", 8) != expected_download_with:
        raise ContractError("blocked prerelease artifact download identity changed")

    if not re.search(
        r"(?m)^\s+-\s+name:\s*Reverify transferred artifact identity without a repository token\s*$",
        transfer_step,
    ):
        raise ContractError("blocked prerelease publish job lacks token-free transfer verification")
    if re.search(
        r"(?m)^\s+(?:if|continue-on-error|shell):", transfer_step
    ):
        raise ContractError("blocked prerelease transfer verification must be unconditional")
    if not re.search(
        r"(?m)^\s+-\s+name:\s*Recheck immutable tag and create draft blocked prerelease\s*$",
        final_publish_step,
    ) or re.search(r"(?m)^\s+(?:if|continue-on-error|shell):", final_publish_step):
        raise ContractError("blocked prerelease must end with one unconditional publish step")
def validate_rc_release_workflow(text: str, source: Path) -> None:
    document = parse_workflow_yaml(text, source)
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != ACTIVE_RC_WORKFLOW_SHA256:
        raise ContractError("active RC workflow differs from the exact reviewed contract")

    root = yaml_mapping(document, source, "workflow")
    on = yaml_mapping(root.get("on"), source, "on")
    dispatch = require_yaml_keys(
        on.get("workflow_dispatch"), ("inputs",), source, "on.workflow_dispatch"
    )
    inputs = require_yaml_keys(
        dispatch["inputs"],
        RC_RELEASE_INPUT_ORDER,
        source,
        "on.workflow_dispatch.inputs",
    )
    if len(inputs) > REPOSITORY_WORKFLOW_DISPATCH_INPUT_LIMIT:
        raise ContractError(
            "active RC workflow exceeds the repository-reviewed workflow_dispatch input limit"
        )
    for input_name, input_node in inputs.items():
        path = f"on.workflow_dispatch.inputs.{input_name}"
        if input_name == "publish_rc_release":
            expected_keys = ("description", "required", "type", "default")
        else:
            expected_keys = ("description", "required", "type")
        values = require_yaml_keys(input_node, expected_keys, source, path)
        if not yaml_scalar(values["description"], source, f"{path}.description").strip():
            raise ContractError(f"workflow {path}.description may not be empty")
        if input_name == "publish_rc_release":
            require_yaml_scalar(
                values["required"],
                "true",
                source,
                f"{path}.required",
                tag="tag:yaml.org,2002:bool",
            )
            require_yaml_scalar(values["type"], "boolean", source, f"{path}.type")
            require_yaml_scalar(
                values["default"],
                "false",
                source,
                f"{path}.default",
                tag="tag:yaml.org,2002:bool",
            )
        elif input_name in {
            "host_run",
            "host_artifact_id",
            "host_artifact_digest",
            "host_challenge",
        }:
            require_yaml_scalar(
                values["required"],
                "false",
                source,
                f"{path}.required",
                tag="tag:yaml.org,2002:bool",
            )
            require_yaml_scalar(values["type"], "string", source, f"{path}.type")
        else:
            require_yaml_scalar(
                values["required"],
                "true",
                source,
                f"{path}.required",
                tag="tag:yaml.org,2002:bool",
            )
            require_yaml_scalar(values["type"], "string", source, f"{path}.type")

    expected_environment = (
        ("GO_VERSION", "1.26.4"),
        ("VERSION", "0.16"),
        ("RC_VERSION", "0.16-rc.2"),
        ("CYCLONEDX_GOMOD_VERSION", "v1.9.0"),
        ("GOVULNCHECK_VERSION", "v1.6.0"),
        ("GH_CLI_VERSION", "2.96.0"),
        (
            "GH_CLI_LINUX_AMD64_SHA256",
            "83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60",
        ),
        ("RC_BUILDER_IMAGE", RC_BUILDER_IMAGE),
        ("RC_BUILDER_IMAGE_DIGEST", RC_BUILDER_IMAGE_DIGEST),
        ("RC_BUILDER_REFERENCE", RC_BUILDER_REFERENCE),
    )
    if exact_string_mapping(root.get("env"), source, "env") != expected_environment:
        raise ContractError(
            "active RC workflow must pin the exact Go, release, and immutable builder identities"
        )
    gh_cli_install_markers = (
        "apt-get install -y build-essential binutils ca-certificates curl file git jq zip unzip nginx",
        'gh_archive="$RUNNER_TEMP/gh_${GH_CLI_VERSION}_linux_amd64.tar.gz"',
        '"https://github.com/cli/cli/releases/download/v${GH_CLI_VERSION}/gh_${GH_CLI_VERSION}_linux_amd64.tar.gz"',
        'printf \'%s  %s\\n\' "$GH_CLI_LINUX_AMD64_SHA256" "$gh_archive" | sha256sum -c -',
        'tar -xzf "$gh_archive" -C "$RUNNER_TEMP" "gh_${GH_CLI_VERSION}_linux_amd64/bin/gh"',
        'install -m 0755 "$gh_root/bin/gh" /usr/local/bin/gh',
        "gh --version",
        "gh help attestation >/dev/null",
    )
    if any(text.count(marker) != 2 for marker in gh_cli_install_markers):
        raise ContractError(
            "active RC workflow must install the exact checksum-pinned GitHub CLI in both job containers"
        )
    top_permissions = require_yaml_keys(
        root.get("permissions"), ("actions", "contents"), source, "permissions"
    )
    require_yaml_scalar(top_permissions["actions"], "read", source, "permissions.actions")
    require_yaml_scalar(top_permissions["contents"], "read", source, "permissions.contents")

    jobs_node = root.get("jobs")
    jobs = require_yaml_keys(
        jobs_node,
        ("admission", "build", "publish", "verify_published"),
        source,
        "jobs",
    )
    admission = yaml_mapping(jobs["admission"], source, "jobs.admission")
    if exact_string_mapping(
        admission.get("outputs"), source, "jobs.admission.outputs"
    ) != (
        (
            "already_public",
            "${{ steps.release_state.outputs.already_public }}",
        ),
        ("ci_run_id", "${{ steps.release_state.outputs.ci_run_id }}"),
        ("ci_run_attempt", "${{ steps.release_state.outputs.ci_run_attempt }}"),
        ("host_run_id", "${{ steps.release_state.outputs.host_run_id }}"),
        ("host_run_attempt", "${{ steps.release_state.outputs.host_run_attempt }}"),
    ):
        raise ContractError(
            "active RC admission must export the reviewed release and run identities"
        )
    admission_steps = yaml_sequence(
        admission.get("steps"), source, "jobs.admission.steps"
    )
    if not admission_steps:
        raise ContractError("active RC admission must retain its release-state step")
    admission_release_state = yaml_mapping(
        admission_steps[0], source, "jobs.admission.steps[0]"
    )
    require_yaml_scalar(
        admission_release_state.get("id"),
        "release_state",
        source,
        "jobs.admission.steps[0].id",
    )

    publish = yaml_mapping(jobs["publish"], source, "jobs.publish")
    publish_needs = yaml_sequence(publish.get("needs"), source, "jobs.publish.needs")
    if tuple(
        yaml_scalar(node, source, f"jobs.publish.needs[{index}]")
        for index, node in enumerate(publish_needs)
    ) != ("admission", "build"):
        raise ContractError(
            "active RC publish must depend on admission and the gated build"
        )
    require_yaml_scalar(
        publish.get("if"),
        "${{ needs.admission.outputs.already_public != 'true' && inputs.publish_rc_release }}",
        source,
        "jobs.publish.if",
    )
    publish_permissions = require_yaml_keys(
        publish.get("permissions"),
        ("actions", "attestations", "contents"),
        source,
        "jobs.publish.permissions",
    )
    require_yaml_scalar(
        publish_permissions["actions"], "read", source, "jobs.publish.permissions.actions"
    )
    require_yaml_scalar(
        publish_permissions["attestations"],
        "read",
        source,
        "jobs.publish.permissions.attestations",
    )
    require_yaml_scalar(
        publish_permissions["contents"],
        "write",
        source,
        "jobs.publish.permissions.contents",
    )
    publish_environment = require_yaml_keys(
        publish.get("environment"), ("name",), source, "jobs.publish.environment"
    )
    require_yaml_scalar(
        publish_environment["name"],
        "round8-rc-publication",
        source,
        "jobs.publish.environment.name",
    )

    build = yaml_mapping(jobs["build"], source, "jobs.build")
    require_yaml_scalar(build.get("needs"), "admission", source, "jobs.build.needs")
    require_yaml_scalar(
        build.get("if"),
        "${{ needs.admission.outputs.already_public != 'true' }}",
        source,
        "jobs.build.if",
    )
    expected_runner_outputs = tuple(
        (
            field,
            f"${{{{ steps.runner_identity.outputs.{field} }}}}",
        )
        for field in (
            "runner_label",
            "runner_os",
            "runner_arch",
            "runner_environment",
            "runner_name",
            "runner_image_os",
            "runner_image_version",
        )
    )
    if (
        exact_string_mapping(build.get("outputs"), source, "jobs.build.outputs")
        != expected_runner_outputs
    ):
        raise ContractError(
            "active RC build must export the exact captured runner identity to publication"
        )
    build_permissions = require_yaml_keys(
        build.get("permissions"),
        ("actions", "attestations", "contents", "id-token"),
        source,
        "jobs.build.permissions",
    )
    for permission, expected in (
        ("actions", "read"),
        ("attestations", "write"),
        ("contents", "read"),
        ("id-token", "write"),
    ):
        require_yaml_scalar(
            build_permissions[permission],
            expected,
            source,
            f"jobs.build.permissions.{permission}",
        )
    require_yaml_scalar(build.get("runs-on"), "ubuntu-24.04", source, "jobs.build.runs-on")
    build_container = require_yaml_keys(
        build.get("container"), ("image",), source, "jobs.build.container"
    )
    require_yaml_scalar(
        build_container["image"],
        RC_BUILDER_REFERENCE,
        source,
        "jobs.build.container.image",
    )
    build_steps = yaml_sequence(build.get("steps"), source, "jobs.build.steps")
    named_build_steps: dict[str, tuple[int, dict[str, Node]]] = {}
    for index, step_node in enumerate(build_steps):
        step = yaml_mapping(step_node, source, f"jobs.build.steps[{index}]")
        name_node = step.get("name")
        if name_node is not None:
            name = yaml_scalar(name_node, source, f"jobs.build.steps[{index}].name")
            named_build_steps[name] = (index, step)
    runner_identity = named_build_steps.get("Bind the exact build runner context")
    candidate_upload = named_build_steps.get("Upload exact verified private Host-test candidate")
    publish_upload = named_build_steps.get("Upload exact verified publication-stage RC assets")
    provenance = named_build_steps.get("Generate signed provenance for exact RC artifacts")
    artifact_build = named_build_steps.get("Build and reproduce exact RC release assets")
    artifact_reverify = named_build_steps.get("Reverify RC artifact allowlist and hashes")
    host_evidence_download = named_build_steps.get(
        "Download and verify publication-only attested Host evidence"
    )
    if (
        runner_identity is None
        or candidate_upload is None
        or publish_upload is None
        or provenance is None
        or artifact_build is None
        or artifact_reverify is None
        or host_evidence_download is None
    ):
        raise ContractError(
            "active RC build must capture runner identity and attest artifacts before both reviewed transfers"
        )
    runner_index, runner_step = runner_identity
    if runner_index != 1:
        raise ContractError(
            "active RC build must capture the runner context immediately after exact checkout"
        )
    require_yaml_keys(
        build_steps[runner_index],
        ("name", "id", "env", "run"),
        source,
        f"jobs.build.steps[{runner_index}]",
    )
    require_yaml_scalar(
        runner_step.get("id"),
        "runner_identity",
        source,
        f"jobs.build.steps[{runner_index}].id",
    )
    expected_runner_capture_env = (
        ("RC_RUNNER_LABEL", "ubuntu-24.04"),
        ("RC_RUNNER_OS", "${{ runner.os }}"),
        ("RC_RUNNER_ARCH", "${{ runner.arch }}"),
        ("RC_RUNNER_ENVIRONMENT", "${{ runner.environment }}"),
        ("RC_RUNNER_NAME", RC_REPRODUCIBLE_RUNNER_NAME),
        ("RC_RUNNER_IMAGE_OS", "UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER"),
        ("RC_RUNNER_IMAGE_VERSION", "UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER"),
    )
    if (
        exact_string_mapping(
            runner_step.get("env"),
            source,
            f"jobs.build.steps[{runner_index}].env",
        )
        != expected_runner_capture_env
    ):
        raise ContractError(
            "active RC build must bind the honest GitHub runner context and explicit unobservable host-image sentinel"
        )
    runner_run = yaml_scalar(
        runner_step.get("run"), source, f"jobs.build.steps[{runner_index}].run"
    )
    runner_run_markers = (
        "unobservable='UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER'",
        '[[ "$RC_RUNNER_LABEL" == ubuntu-24.04 ]]',
        '[[ "$RC_RUNNER_OS" == Linux ]]',
        '[[ "$RC_RUNNER_ARCH" == X64 ]]',
        '[[ "$RC_RUNNER_ENVIRONMENT" == github-hosted ]]',
        f'[[ "$RC_RUNNER_NAME" == {RC_REPRODUCIBLE_RUNNER_NAME} ]]',
        '[[ "$RC_RUNNER_IMAGE_OS" == "$unobservable" ]]',
        '[[ "$RC_RUNNER_IMAGE_VERSION" == "$unobservable" ]]',
        "printf 'runner_label=%s\\n' \"$RC_RUNNER_LABEL\"",
        "printf 'runner_os=%s\\n' \"$RC_RUNNER_OS\"",
        "printf 'runner_arch=%s\\n' \"$RC_RUNNER_ARCH\"",
        "printf 'runner_environment=%s\\n' \"$RC_RUNNER_ENVIRONMENT\"",
        "printf 'runner_name=%s\\n' \"$RC_RUNNER_NAME\"",
        "printf 'runner_image_os=%s\\n' \"$RC_RUNNER_IMAGE_OS\"",
        "printf 'runner_image_version=%s\\n' \"$RC_RUNNER_IMAGE_VERSION\"",
        '} >>"$GITHUB_OUTPUT"',
    )
    if any(runner_run.count(marker) != 1 for marker in runner_run_markers):
        raise ContractError(
            "active RC runner identity capture must validate and export every reviewed field exactly once"
        )

    artifact_build_index, artifact_build_step = artifact_build
    artifact_build_env = yaml_mapping(
        artifact_build_step.get("env"),
        source,
        f"jobs.build.steps[{artifact_build_index}].env",
    )
    artifact_reverify_index, artifact_reverify_step = artifact_reverify
    artifact_reverify_env = yaml_mapping(
        artifact_reverify_step.get("env"),
        source,
        f"jobs.build.steps[{artifact_reverify_index}].env",
    )
    for field in (
        "LABEL",
        "OS",
        "ARCH",
        "ENVIRONMENT",
        "NAME",
        "IMAGE_OS",
        "IMAGE_VERSION",
    ):
        output_name = field.lower()
        require_yaml_scalar(
            artifact_build_env.get(f"RC_RUNNER_{field}"),
            f"${{{{ steps.runner_identity.outputs.runner_{output_name} }}}}",
            source,
            f"jobs.build.steps[{artifact_build_index}].env.RC_RUNNER_{field}",
        )
        require_yaml_scalar(
            artifact_reverify_env.get(f"EXPECTED_RUNNER_{field}"),
            f"${{{{ steps.runner_identity.outputs.runner_{output_name} }}}}",
            source,
            f"jobs.build.steps[{artifact_reverify_index}].env.EXPECTED_RUNNER_{field}",
        )
    artifact_reverify_run = yaml_scalar(
        artifact_reverify_step.get("run"),
        source,
        f"jobs.build.steps[{artifact_reverify_index}].run",
    )
    for field in (
        "label",
        "os",
        "arch",
        "environment",
        "name",
        "image_os",
        "image_version",
    ):
        if (
            f'--arg runner_{field} "$EXPECTED_RUNNER_{field.upper()}"' not in artifact_reverify_run
            or f".runner_{field} == $runner_{field}" not in artifact_reverify_run
        ):
            raise ContractError(
                "active RC build must reverify every emitted runner identity field"
            )
    host_evidence_index, host_evidence_step = host_evidence_download
    host_evidence_run = yaml_scalar(
        host_evidence_step.get("run"),
        source,
        f"jobs.build.steps[{host_evidence_index}].run",
    )
    host_zip_markers = (
        '--argjson max_size 1048576',
        "host_archive_max_bytes=1048576",
        '[[ "$downloaded_archive_size" == "$host_archive_size" ]]',
        "downloaded_archive_size > 0 && downloaded_archive_size <= host_archive_max_bytes",
        'python3 -B - "$archive" "$host_dir" <<\'PY\'',
        "MAX_ENTRIES = 2\n",
        "MAX_ENTRY_EXPANDED_BYTES = 16384\n",
        "MAX_TOTAL_EXPANDED_BYTES = 24576\n",
        "len(names) != len(set(names))",
        "set(names) != EXPECTED_NAMES",
        'or ".." in path.parts',
        "or entry.is_dir()",
        "or stat.S_ISDIR(mode)",
        "if stat.S_ISLNK(mode):",
        "if file_type not in (0, stat.S_IFREG):",
        "if not 0 < entry.file_size <= MAX_ENTRY_EXPANDED_BYTES:",
        "if total_declared > MAX_TOTAL_EXPANDED_BYTES:",
        'with host_zip.open(entry, "r") as source, target.open("xb") as output:',
        "if entry_written > MAX_ENTRY_EXPANDED_BYTES:",
        "if total_written > MAX_TOTAL_EXPANDED_BYTES:",
        "if entry_written != entry.file_size:",
        "if total_written != total_declared:",
    )
    if any(host_evidence_run.count(marker) != 1 for marker in host_zip_markers):
        raise ContractError(
            "active RC Host artifact ingestion must cap compressed and expanded ZIP data and extract only reviewed regular entries"
        )
    api_artifact_size_guard = re.compile(
        r'\(\.size_in_bytes\s*\|\s*type == "number" and \. == floor and '
        r'\. > 0 and \. <= \$max_size\)'
    )
    selected_artifact_size_guard = re.compile(
        r'\.size_in_bytes\s*\|\s*select\(type == "number" and \. == floor and '
        r'\. > 0 and \. <= \$max_size\)'
    )
    if (
        len(api_artifact_size_guard.findall(host_evidence_run)) != 1
        or len(selected_artifact_size_guard.findall(host_evidence_run)) != 1
    ):
        raise ContractError(
            "active RC Host artifact ingestion must enforce the GitHub size_in_bytes limit before download"
        )
    if 'unzip -q "$archive"' in host_evidence_run:
        raise ContractError(
            "active RC Host artifact ingestion must not use an unbounded unzip extraction path"
        )
    host_zip_order = (
        host_evidence_run.index("host_archive_max_bytes=1048576"),
        host_evidence_run.index('host_archive_size="$(jq -er'),
        host_evidence_run.index(
            '"repos/${GITHUB_REPOSITORY}/actions/artifacts/${HOST_ARTIFACT_ID}/zip" >"$archive"'
        ),
        host_evidence_run.index(
            '[[ "$downloaded_archive_size" == "$host_archive_size" ]]'
        ),
        host_evidence_run.index(
            '[[ "sha256:$(sha256sum "$archive" | awk \'{print $1}\')" == "$HOST_ARTIFACT_DIGEST" ]]'
        ),
        host_evidence_run.index('python3 -B - "$archive" "$host_dir" <<\'PY\''),
        host_evidence_run.index('evidence="$host_dir/round8-host-evidence.json"'),
    )
    if host_zip_order != tuple(sorted(host_zip_order)):
        raise ContractError(
            "active RC Host artifact ingestion must verify API size, downloaded size, digest, and safe ZIP contents before extraction use"
        )
    candidate_index, candidate_step = candidate_upload
    publish_index, publish_step = publish_upload
    provenance_index, provenance_step = provenance
    if not provenance_index < candidate_index < publish_index:
        raise ContractError("active RC provenance must be generated before either artifact transfer")
    require_yaml_scalar(
        provenance_step.get("uses"),
        RC_PROVENANCE_ACTION,
        source,
        f"jobs.build.steps[{provenance_index}].uses",
    )
    provenance_with = require_yaml_keys(
        provenance_step.get("with"),
        ("subject-path",),
        source,
        f"jobs.build.steps[{provenance_index}].with",
    )
    require_yaml_scalar(
        provenance_with["subject-path"],
        "dist/*",
        source,
        f"jobs.build.steps[{provenance_index}].with.subject-path",
    )
    if "if" in provenance_step or "continue-on-error" in provenance_step:
        raise ContractError("active RC provenance generation must be unconditional and fail closed")
    require_yaml_scalar(
        candidate_step.get("if"),
        "${{ !inputs.publish_rc_release }}",
        source,
        f"jobs.build.steps[{candidate_index}].if",
    )
    require_yaml_scalar(
        publish_step.get("if"),
        "${{ inputs.publish_rc_release }}",
        source,
        f"jobs.build.steps[{publish_index}].if",
    )
    candidate_with = yaml_mapping(
        candidate_step.get("with"), source, f"jobs.build.steps[{candidate_index}].with"
    )
    publish_with = yaml_mapping(
        publish_step.get("with"), source, f"jobs.build.steps[{publish_index}].with"
    )
    candidate_paths = tuple(
        line.strip()
        for line in yaml_scalar(
            candidate_with.get("path"),
            source,
            f"jobs.build.steps[{candidate_index}].with.path",
        ).splitlines()
        if line.strip()
    )
    publish_paths = tuple(
        line.strip()
        for line in yaml_scalar(
            publish_with.get("path"),
            source,
            f"jobs.build.steps[{publish_index}].with.path",
        ).splitlines()
        if line.strip()
    )
    expected_host_paths = (
        "dist/round8-host-evidence.json",
        "dist/round8-host-evidence.json.sha256",
    )
    if len(candidate_paths) != 17 or any(path in candidate_paths for path in expected_host_paths):
        raise ContractError("private Host-test candidate upload must contain exactly 17 non-Host assets")
    if len(publish_paths) != 19 or publish_paths[-2:] != expected_host_paths:
        raise ContractError("publication-stage upload must contain exactly 19 assets including Host evidence")

    publish_steps = yaml_sequence(publish.get("steps"), source, "jobs.publish.steps")
    expected_publish_step_names = (
        "Download exact verified RC assets",
        "Reverify transferred RC assets without repository source",
        "Recheck immutable tag and main before publication",
        "Create, byte-check, and publish v0.16-rc.2 prerelease",
    )
    if len(publish_steps) != len(expected_publish_step_names):
        raise ContractError("active RC publish job must contain exactly four reviewed steps")
    parsed_publish_steps: list[dict[str, Node]] = []
    for index, (step_node, expected_name) in enumerate(
        zip(publish_steps, expected_publish_step_names)
    ):
        step = yaml_mapping(step_node, source, f"jobs.publish.steps[{index}]")
        require_yaml_scalar(
            step.get("name"), expected_name, source, f"jobs.publish.steps[{index}].name"
        )
        if "if" in step or "continue-on-error" in step:
            raise ContractError("active RC publish verification and publication steps must fail closed")
        parsed_publish_steps.append(step)

    transfer_run = yaml_scalar(
        parsed_publish_steps[1].get("run"), source, "jobs.publish.steps[1].run"
    )
    transfer_env = yaml_mapping(
        parsed_publish_steps[1].get("env"), source, "jobs.publish.steps[1].env"
    )
    for field in (
        "LABEL",
        "OS",
        "ARCH",
        "ENVIRONMENT",
        "NAME",
        "IMAGE_OS",
        "IMAGE_VERSION",
    ):
        output_name = field.lower()
        require_yaml_scalar(
            transfer_env.get(f"BUILD_RUNNER_{field}"),
            f"${{{{ needs.build.outputs.runner_{output_name} }}}}",
            source,
            f"jobs.publish.steps[1].env.BUILD_RUNNER_{field}",
        )
    for field in (
        "label",
        "os",
        "arch",
        "environment",
        "name",
        "image_os",
        "image_version",
    ):
        if (
            f'--arg runner_{field} "$BUILD_RUNNER_{field.upper()}"' not in transfer_run
            or f".runner_{field} == $runner_{field}" not in transfer_run
        ):
            raise ContractError(
                "active RC publication must reverify every build runner identity field from job outputs"
            )
    expected_start = 'expected="$(printf \'%s\\n\' \\\n'
    expected_end = ' | LC_ALL=C sort)"'
    start = transfer_run.find(expected_start)
    end = transfer_run.find(expected_end, start + len(expected_start))
    if start < 0 or end < 0:
        raise ContractError("active RC transfer verification must enumerate the exact publication assets")
    expected_block = transfer_run[start + len(expected_start) : end]
    transfer_assets = tuple(
        match.group(1)
        for match in re.finditer(r"(?m)^\s*([A-Za-z0-9_.-]+)\s*(?:\\)?$", expected_block)
    )
    expected_asset_names = tuple(sorted(Path(path).name for path in publish_paths))
    if len(transfer_assets) != 19 or tuple(sorted(transfer_assets)) != expected_asset_names:
        raise ContractError("active RC transfer verification must cover exactly all 19 assets")
    for marker in (
        'actual="$(find dist -mindepth 1 -maxdepth 1 -printf \'%f\\n\' | LC_ALL=C sort)"',
        '[[ "$actual" == "$expected" ]]',
        'ordinary_assets="$(grep -Fvx',
        '-e round8-host-evidence.json',
        '-e round8-host-evidence.json.sha256 <<<"$expected")"',
        '[[ "$(grep -c . <<<"$ordinary_assets")" == 17 ]]',
        'done <<<"$ordinary_assets"',
    ):
        if marker not in transfer_run:
            raise ContractError(
                "active RC transfer verification must verify all 19 bytesets and exactly 17 ordinary release attestations"
            )
    ordinary_transfer_attestation = re.compile(
        r'(?m)^\s*if gh attestation verify "dist/\$name" \\\n'
        r'\s*--repo "\$GITHUB_REPOSITORY" \\\n'
        r'\s*--signer-workflow "\$GITHUB_REPOSITORY/\.github/workflows/release-rc\.yml" \\\n'
        r'\s*--signer-digest "\$EXPECTED_COMMIT" \\\n'
        r'\s*--source-ref "refs/tags/\$TAG" \\\n'
        r'\s*--source-digest "\$EXPECTED_COMMIT" >/dev/null; then$'
    )
    if len(ordinary_transfer_attestation.findall(transfer_run)) != 1:
        raise ContractError(
            "active RC transfer verification must bind ordinary asset attestations to the exact release workflow, tag, and commit"
        )
    if transfer_run.count("gh attestation verify") != 2:
        raise ContractError(
            "active RC transfer verification must contain only the reviewed Host and ordinary-asset attestation checks"
        )

    immutability_run = yaml_scalar(
        parsed_publish_steps[2].get("run"), source, "jobs.publish.steps[2].run"
    )
    for marker in (
        '"repos/${GITHUB_REPOSITORY}/immutable-releases"',
        '[[ "$(jq -r \'.enabled\' <<<"$immutability")" == true ]]',
        '"repos/${GITHUB_REPOSITORY}/releases/latest"',
        '[[ "$latest_tag" == v0.15 ]]',
        '[[ "$(jq -r \'.object.sha\' <<<"$main_ref")" == "$EXPECTED_COMMIT" ]]',
        '[[ "$tag_object_sha" == "$EXPECTED_TAG_OBJECT" ]]',
        '[[ "$(jq -r \'.tree.sha\' <<<"$commit_object")" == "$EXPECTED_TREE" ]]',
    ):
        if marker not in immutability_run:
            raise ContractError(
                "active RC publication precheck must require immutable Releases, v0.15 latest, and exact remote identity"
            )

    admission_text = job_blocks(text)["admission"]
    build_text = job_blocks(text)["build"]
    publish_text = job_blocks(text)["publish"]
    verify_published_text = job_blocks(text)["verify_published"]
    admission_contracts = (
        '[[ "$CI_RUN" =~ ^([1-9][0-9]*):([1-9][0-9]*)$ ]]',
        'CI_RUN_ID="${BASH_REMATCH[1]}"',
        'CI_RUN_ATTEMPT="${BASH_REMATCH[2]}"',
        'if [[ -n "$HOST_RUN" ]]; then',
        '[[ "$HOST_RUN" =~ ^([1-9][0-9]*):([1-9][0-9]*)$ ]]',
        'HOST_RUN_ID="${BASH_REMATCH[1]}"',
        'HOST_RUN_ATTEMPT="${BASH_REMATCH[2]}"',
        "already_public=false",
        'if [[ "$(jq -r \'length\' <<<"$matches")" == 1 ]]; then',
        'if [[ "$(jq -r \'.draft\' <<<"$release")" == true ]]; then',
        ".prerelease == true and",
        "([.assets[].name] - [",
        '.immutable == true and .prerelease == true and',
        ".target_commitish == $commit and",
        'length == 19 and all(.state == "uploaded") and',
        "already_public=true",
        'if [[ "$already_public" == true && "$host_values_present" == 0 ]]; then',
        'elif [[ "$PUBLISH_RC_RELEASE" == true ]]; then',
        '[[ "$HOST_RUN_ID" =~ ^[1-9][0-9]*$ ]]',
        '[[ "$HOST_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]',
        '[[ "$HOST_ARTIFACT_ID" =~ ^[1-9][0-9]*$ ]]',
        '[[ "$HOST_ARTIFACT_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]',
        '[[ "$HOST_CHALLENGE" =~ ^[0-9a-f]{64}$ ]]',
        'printf \'already_public=%s\\n\' "$already_public" >>"$GITHUB_OUTPUT"',
        'printf \'ci_run_id=%s\\n\' "$CI_RUN_ID" >>"$GITHUB_OUTPUT"',
        'printf \'ci_run_attempt=%s\\n\' "$CI_RUN_ATTEMPT" >>"$GITHUB_OUTPUT"',
        'printf \'host_run_id=%s\\n\' "$HOST_RUN_ID" >>"$GITHUB_OUTPUT"',
        'printf \'host_run_attempt=%s\\n\' "$HOST_RUN_ATTEMPT" >>"$GITHUB_OUTPUT"',
    )
    if any(marker not in admission_text for marker in admission_contracts):
        raise ContractError(
            "active RC admission must route draft/new releases to build and immutable public releases to read-only verification"
        )
    if admission_text.count("already_public=true") != 1:
        raise ContractError(
            "active RC admission must set already_public only after exact immutable release validation"
        )
    admission_run_texts = tuple(
        yaml_scalar(
            run_node,
            source,
            f"jobs.admission.steps[{index}].run",
        )
        for index, step_node in enumerate(admission_steps)
        for run_node in (yaml_mapping(
            step_node, source, f"jobs.admission.steps[{index}]"
        ).get("run"),)
        if run_node is not None
    )
    if (
        re.search(
            r"(?im)(?:gh\s+release\s+(?:create|edit|upload|delete)|"
            r"actions/(?:upload-artifact|attest-build-provenance|cache)@)",
            admission_text,
        )
        or any(
            read_only_gh_api_mutation_reason(run_text) is not None
            for run_text in admission_run_texts
        )
    ):
        raise ContractError("active RC admission must remain read-only")
    build_contracts = (
        "Download and verify publication-only attested Host evidence",
        '.path == ".github/workflows/round8-host-validation.yml"',
        '.digest == $digest and .expired == false',
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/round8-host-validation.yml"',
        '--signer-digest "$EXPECTED_COMMIT"',
        '--source-ref "refs/tags/$TAG"',
        '--source-digest "$EXPECTED_COMMIT"',
        'execution.get("trust") != "GITHUB_ATTESTED_ROUND8_HOST_WORKFLOW"',
        'execution.get("challenge") != expected_challenge',
        'sandbox.get("locality_challenge") != "PASS"',
        "duplicate JSON key",
        "def strict_json_equal(actual, expected):",
        "if type(actual) is not type(expected):",
        "Host evidence JSON must be canonical UTF-8 without trailing bytes",
        'separators=(",", ":")',
        '"validation_scope": "CPA_HOST_COUNTED_MOCK_ONLY"',
        '"real_provider_contacted": False',
        '"production_accessed": False',
        '"unexpected_restart_count": 0',
        '"chat_benign_upstream": 1',
        '"chat_malicious_upstream": 0',
        '"responses_benign_upstream": 1',
        '"responses_malicious_upstream": 0',
        '"benign_total": 42',
        '"benign_passed": 42',
        '"paired_malicious_total": 42',
        '"paired_malicious_blocked": 42',
        '"balanced_incomplete_allow": True',
        '"strict_incomplete_block": True',
        '"usage_queue_allow_delta": 1',
        '"usage_queue_blocked_zero": True',
        '"only_blocked_passed": True',
        '"ttl_dedup_passed": True',
        '"schema_v3_redaction_metadata_passed": True',
        '"purge_wal_passed": True',
        '"quick_check": "ok"',
        '"schema_version": 5',
        '"migration_versions": [1, 2, 3, 4, 5]',
        '"contract": "round8-counted-mock/v1"',
        '"source": "https://github.com/yujianwudi/cyber-abuse-guard-next"',
        'or mock.get("revision") != expected_commit',
        '"revision": expected_commit',
        '"tag": "v0.16-rc.2"',
        '"tree": expected_tree',
        're.fullmatch(r"sha256:[0-9a-f]{64}", mock["image_id"])',
        're.fullmatch(r"sha256:[0-9a-f]{64}", entry["image_id"])',
        'rfc3339.fullmatch(entry["build_date"])',
        f'("primary", "{CPA_ROUND8_VERSION}", "{CPA_ROUND8_COMMIT}"),',
        f'"version": "{CPA_ROUND8_VERSION}",',
        f'"commit": "{CPA_ROUND8_COMMIT}",',
        '"image_id": cpa_identities["primary"]["image_id"]',
        '"build_date": cpa_identities["primary"]["build_date"]',
        '"restart_cycle_passed": True',
        "RC_PUBLISH_RELEASE: ${{ inputs.publish_rc_release }}",
        '--arg builder_reference "$RC_BUILDER_REFERENCE"',
        '.builder_reference == ($builder_image + "@" + $builder_image_digest)',
        "expected_count=17",
        "expected_count=19",
        '.release_phase == $phase and .publish_rc_release == $publish',
        ".artifact_count == $artifact_count",
    )
    if any(marker not in build_text for marker in build_contracts):
        raise ContractError("active RC build does not enforce the reviewed 17/19-asset Host evidence contract")
    if build_text.count('"unexpected_restart_count": 0') != 2:
        raise ContractError("active RC Host evidence must lock primary and top-level unexpected restart counts")
    if build_text.count('"image_id": cpa_identities[') != 1 or build_text.count(
        '"build_date": cpa_identities['
    ) != 1:
        raise ContractError(
            f"active RC Host evidence must retain the immutable CPA {CPA_ROUND8_VERSION} image identity"
        )
    manifest_result_markers = (
        "chat_benign_upstream: 1",
        "chat_malicious_upstream: 0",
        "responses_benign_upstream: 1",
        "responses_malicious_upstream: 0",
        "benign_total: 42",
        "benign_passed: 42",
        "paired_malicious_total: 42",
        "paired_malicious_blocked: 42",
        "balanced_incomplete_allow: true",
        "strict_incomplete_block: true",
        "usage_queue_allow_delta: 1",
        "usage_queue_blocked_zero: true",
        "only_blocked_passed: true",
        "ttl_dedup_passed: true",
        "schema_v3_redaction_metadata_passed: true",
        "purge_wal_passed: true",
        'quick_check: "ok"',
        "schema_version: 5",
        "migration_versions: [1, 2, 3, 4, 5]",
        "restart_cycle_passed: true",
    )
    if any(text.count(marker) != 2 for marker in manifest_result_markers):
        raise ContractError("active RC manifest checks must lock both copies of the detailed Host result matrix")
    if text.count("unexpected_restart_count: 0") != 4:
        raise ContractError("active RC manifest checks must lock lane and top-level unexpected restart counts")
    publish_contracts = (
        "round8-host-evidence.json.sha256",
        ".artifact_count == 19",
        '.assets | length == 19 and all(.state == "uploaded")',
        "cleanup_publication_exit()",
        "trap cleanup_publication_exit EXIT",
        "publish_response=''",
        "publish_request_returned=0",
        'if publish_response="$(gh api --method PATCH',
        "publish_request_returned=1",
        "for attempt in 1 2 3 4 5; do",
        '[[ "$(jq -r \'.draft\' <<<"$candidate_final")" == false ]]',
        '[[ "$(jq -r \'.immutable\' <<<"$candidate_final")" == true ]]',
        '[[ -n "$final" ]] || {',
        "immutable RC publication did not reach a verifiable public terminal state",
        "--prerelease",
        "--latest=false",
        "make_latest=false",
        '[[ "$latest_tag" == v0.15 ]]',
        "phase1_assets=(",
        "host_assets=(",
        "download_and_compare_asset()",
        "missing_phase1_assets=()",
        'missing_phase1_assets+=("dist/$name")',
        'gh release upload "$TAG" "${missing_phase1_assets[@]}"',
        "phase1_fingerprint=",
        "missing_host_assets=()",
        'gh release upload "$TAG" "${missing_host_assets[@]}"',
        "ATTESTED_PROTECTED_HOST_WORKFLOW_ARTIFACT",
        "SIGNER_WORKFLOW_REF_COMMIT_RUN_ARTIFACT_DIGEST_CHALLENGE_AND_SANDBOX_LOCALITY_VERIFIED",
        "Phase 2 Host evidence was generated and signed by the protected Round 8 Host",
        'name \\`${BUILD_RUNNER_NAME}\\`',
        'download_and_compare_asset "$name" immutable-final',
        'download_and_compare_asset "$name" already-public',
        "already-public immutable RC release verified without mutation",
    )
    if any(marker not in publish_text for marker in publish_contracts):
        raise ContractError("active RC publish job does not enforce the 19-asset non-latest prerelease contract")
    if "--clobber" in publish_text:
        raise ContractError("active RC publish job must never overwrite an existing release asset")
    try:
        recovery_start = publish_text.index(
            'if [[ "$(jq -r \'.draft\' <<<"$release")" == false ]]; then'
        )
        recovery_end = publish_text.index("exit 0", recovery_start)
    except ValueError as error:
        raise ContractError(
            "active RC already-public recovery must have a closed read-only terminal branch"
        ) from error
    recovery_text = publish_text[recovery_start:recovery_end]
    for marker in (
        '[[ "$(jq -r \'.immutable\' <<<"$release")" == true ]]',
        '[[ "$(jq -r \'.prerelease\' <<<"$release")" == true ]]',
        '[[ "$(jq -r \'.target_commitish\' <<<"$release")" == "$EXPECTED_COMMIT" ]]',
        '[[ "$(jq -r \'.name\' <<<"$release")" == "$release_title" ]]',
        '[[ "$(jq -r \'.body\' <<<"$release")" == "$expected_body" ]]',
        '.assets | length == 19 and',
        'download_and_compare_asset "$name" already-public',
        "assert_remote_identity",
    ):
        if marker not in recovery_text:
            raise ContractError(
                "active RC already-public recovery must verify immutable metadata, all 19 bytes, and remote identity"
            )
    if any(
        forbidden in recovery_text
        for forbidden in (
            "gh release upload",
            "gh release edit",
            "--method PATCH",
            "-F draft=false",
        )
    ):
        raise ContractError(
            "active RC already-public recovery must be read-only"
        )
    if not recovery_end < publish_text.index('gh release create "$TAG"', recovery_end):
        raise ContractError(
            "active RC already-public recovery must exit before draft creation or mutation"
        )
    phase1_repair_order = (
        publish_text.index('download_and_compare_asset "$name" preexisting'),
        publish_text.index("missing_phase1_assets=()"),
        publish_text.index('gh release upload "$TAG" "${missing_phase1_assets[@]}"'),
        publish_text.index("existing_phase1_assets="),
        publish_text.index('download_and_compare_asset "$name" phase1'),
        publish_text.index("phase1_fingerprint="),
    )
    if phase1_repair_order != tuple(sorted(phase1_repair_order)):
        raise ContractError(
            "active RC Phase 1 repair must compare existing bytes, upload only missing assets, and reverify before fingerprinting"
        )
    cleanup_trap_position = publish_text.index("trap cleanup_publication_exit EXIT")
    public_transition_position = publish_text.index("-F draft=false", cleanup_trap_position)
    immutable_publication_order = (
        cleanup_trap_position,
        publish_text.index(
            '"repos/${GITHUB_REPOSITORY}/immutable-releases"', cleanup_trap_position
        ),
        publish_text.index("draft_fingerprint="),
        public_transition_position,
        publish_text.index("for attempt in 1 2 3 4 5; do", public_transition_position),
        publish_text.index(".immutable' <<<\"$candidate_final\"") ,
        publish_text.index('.assets | length == 19 and all(.state == "uploaded")'),
        publish_text.index('download_and_compare_asset "$name" immutable-final'),
    )
    if immutable_publication_order != tuple(sorted(immutable_publication_order)):
        raise ContractError(
            "active RC publication must verify the immutable terminal state before final 19-asset byte comparison"
        )
    for forbidden in (
        "restore_release_to_draft",
        "reconcile_publication_exit",
        "publication_reconcile_armed",
        "-F draft=true",
    ):
        if forbidden in publish_text:
            raise ContractError(
                "active RC immutable publication must not attempt an impossible draft rollback"
            )

    verify_published = yaml_mapping(
        jobs["verify_published"], source, "jobs.verify_published"
    )
    require_yaml_scalar(
        verify_published.get("needs"),
        "admission",
        source,
        "jobs.verify_published.needs",
    )
    require_yaml_scalar(
        verify_published.get("if"),
        "${{ needs.admission.outputs.already_public == 'true' }}",
        source,
        "jobs.verify_published.if",
    )
    verify_permissions = require_yaml_keys(
        verify_published.get("permissions"),
        ("actions", "attestations", "contents"),
        source,
        "jobs.verify_published.permissions",
    )
    for permission in ("actions", "attestations", "contents"):
        require_yaml_scalar(
            verify_permissions[permission],
            "read",
            source,
            f"jobs.verify_published.permissions.{permission}",
        )
    require_yaml_scalar(
        verify_published.get("runs-on"),
        "ubuntu-24.04",
        source,
        "jobs.verify_published.runs-on",
    )
    verify_container = require_yaml_keys(
        verify_published.get("container"),
        ("image",),
        source,
        "jobs.verify_published.container",
    )
    require_yaml_scalar(
        verify_container["image"],
        RC_BUILDER_REFERENCE,
        source,
        "jobs.verify_published.container.image",
    )
    require_yaml_scalar(
        verify_published.get("timeout-minutes"),
        "120",
        source,
        "jobs.verify_published.timeout-minutes",
        tag="tag:yaml.org,2002:int",
    )

    verify_steps = yaml_sequence(
        verify_published.get("steps"), source, "jobs.verify_published.steps"
    )
    expected_verify_step_names = (
        "Checkout exact RC tag with restricted data excluded",
        "Recheck restricted-data and workflow contracts",
        "Verify immutable public-rebuild source identity",
        "Set up pinned Go without cache writes",
        "Install bounded public-rebuild dependencies",
        "Download and bind the immutable public RC without mutation",
        "Run complete Linux public-rebuild gates and write canonical summary",
        "Rebuild the exact 19-asset public candidate locally",
        "Byte-compare rebuilt and published assets and recheck public identity",
    )
    if len(verify_steps) != len(expected_verify_step_names):
        raise ContractError(
            "active RC public verifier must contain the exact nine reviewed read-only rebuild steps"
        )
    parsed_verify_steps: list[dict[str, Node]] = []
    for index, (step_node, expected_name) in enumerate(
        zip(verify_steps, expected_verify_step_names)
    ):
        step = yaml_mapping(
            step_node, source, f"jobs.verify_published.steps[{index}]"
        )
        require_yaml_scalar(
            step.get("name"),
            expected_name,
            source,
            f"jobs.verify_published.steps[{index}].name",
        )
        if "if" in step or "continue-on-error" in step:
            raise ContractError(
                "active RC public verifier steps must be unconditional and fail closed"
            )
        parsed_verify_steps.append(step)

    verify_checkout = parsed_verify_steps[0]
    require_yaml_scalar(
        verify_checkout.get("uses"),
        "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        source,
        "jobs.verify_published.steps[0].uses",
    )
    verify_checkout_with = yaml_mapping(
        verify_checkout.get("with"), source, "jobs.verify_published.steps[0].with"
    )
    for key, expected in (
        ("ref", "${{ inputs.tag }}"),
        ("fetch-depth", "0"),
        ("persist-credentials", "false"),
        ("filter", "blob:none"),
        ("sparse-checkout-cone-mode", "false"),
    ):
        require_yaml_scalar(
            verify_checkout_with.get(key),
            expected,
            source,
            f"jobs.verify_published.steps[0].with.{key}",
        )
    verify_sparse_patterns = tuple(
        line.strip()
        for line in yaml_scalar(
            verify_checkout_with.get("sparse-checkout"),
            source,
            "jobs.verify_published.steps[0].with.sparse-checkout",
        ).splitlines()
        if line.strip()
    )
    if verify_sparse_patterns != ROUND6_SPARSE_PATTERNS:
        raise ContractError(
            "active RC public verifier checkout must retain the exact restricted sparse patterns"
        )

    verify_contract_run = yaml_scalar(
        parsed_verify_steps[1].get("run"),
        source,
        "jobs.verify_published.steps[1].run",
    )
    for marker in (
        "python3 -B scripts/round6_safe_gate_contract_test.py",
        "python3 -B scripts/round6_safe_gate_contract.py --root .",
    ):
        if marker not in verify_contract_run:
            raise ContractError(
                "active RC public verifier must recheck the safe-gate contracts"
            )

    verify_source_run = yaml_scalar(
        parsed_verify_steps[2].get("run"),
        source,
        "jobs.verify_published.steps[2].run",
    )
    for marker in (
        '[[ "$GITHUB_REF" == "refs/tags/$TAG" ]]',
        '[[ "$GITHUB_SHA" == "$EXPECTED_COMMIT" ]]',
        '[[ "$GITHUB_WORKFLOW_SHA" == "$EXPECTED_COMMIT" ]]',
        '[[ "$(git rev-parse HEAD)" == "$EXPECTED_COMMIT" ]]',
        '[[ "$(git rev-parse \'HEAD^{tree}\')" == "$EXPECTED_TREE" ]]',
        '[[ "$(git rev-parse "$TAG^{tag}")" == "$EXPECTED_TAG_OBJECT" ]]',
        '! git show-ref --verify --quiet refs/tags/v0.16',
    ):
        if marker not in verify_source_run:
            raise ContractError(
                "active RC public verifier must bind the exact annotated RC tag source"
            )

    verify_setup_go = parsed_verify_steps[3]
    require_yaml_scalar(
        verify_setup_go.get("uses"),
        "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
        source,
        "jobs.verify_published.steps[3].uses",
    )
    verify_setup_go_with = require_yaml_keys(
        verify_setup_go.get("with"),
        ("go-version", "cache"),
        source,
        "jobs.verify_published.steps[3].with",
    )
    require_yaml_scalar(
        verify_setup_go_with["go-version"],
        "${{ env.GO_VERSION }}",
        source,
        "jobs.verify_published.steps[3].with.go-version",
    )
    require_yaml_scalar(
        verify_setup_go_with["cache"],
        "false",
        source,
        "jobs.verify_published.steps[3].with.cache",
        tag="tag:yaml.org,2002:bool",
    )

    verify_download_run = yaml_scalar(
        parsed_verify_steps[5].get("run"),
        source,
        "jobs.verify_published.steps[5].run",
    )
    verify_download_start = verify_download_run.find(
        'expected_assets="$(printf \'%s\\n\' \\\n'
    )
    verify_download_end = verify_download_run.find(
        expected_end, verify_download_start + 1
    )
    if verify_download_start < 0 or verify_download_end < 0:
        raise ContractError(
            "active RC public verifier must enumerate the exact published assets"
        )
    verify_download_block = verify_download_run[
        verify_download_start
        + len('expected_assets="$(printf \'%s\\n\' \\\n') : verify_download_end
    ]
    verify_download_assets = tuple(
        match.group(1)
        for match in re.finditer(
            r"(?m)^\s*([A-Za-z0-9_.-]+)\s*(?:\\)?$", verify_download_block
        )
    )
    if (
        len(verify_download_assets) != 19
        or tuple(sorted(verify_download_assets)) != expected_asset_names
    ):
        raise ContractError(
            "active RC public verifier must download exactly the reviewed 19 assets"
        )
    for marker in (
        'published="$RUNNER_TEMP/published"',
        'expected_digest="$(jq -er \'.digest | select(type == "string" and test("^sha256:[0-9a-f]{64}$"))\' <<<"$asset")"',
        '"repos/${GITHUB_REPOSITORY}/releases/assets/${asset_id}" >"$output"',
        '[[ "sha256:$(sha256sum "$output" | awk \'{print $1}\')" == "$expected_digest" ]]',
        'install -m 0644 "$published/round8-host-evidence.json"',
        "sha256sum -c round8-host-evidence.json.sha256",
    ):
        if marker not in verify_download_run:
            raise ContractError(
                "active RC public verifier must bind every downloaded asset digest and Host evidence"
            )

    verify_gates_run = yaml_scalar(
        parsed_verify_steps[6].get("run"),
        source,
        "jobs.verify_published.steps[6].run",
    )
    for marker in (
        "make round6-format-check round6-git-diff-check round6-module-verify",
        "make cpa-host-fixture-contract",
        "make round4-regression round5-regression round6-regression",
        "make unit-test race round6-vet fuzz-smoke round6-script-test",
        "make management-proxy-413-test corpus-regression",
        "make development-public-jailbreak-corpus round6-benchmark round6-vulncheck",
        "make cpa-latest-compat",
        "make ARTIFACT_VERSION=${RC_VERSION} integration-test",
        "make clean-tree-check",
        "'CPA Cyber Abuse Guard v0.16-rc.2 canonical internal Linux release gates'",
        "'summary_schema=1'",
        '"commit=$RELEASE_RC_EXPECTED_COMMIT"',
        '"tree=$RELEASE_RC_EXPECTED_TREE"',
        '"exact_main_ci_run=$CI_RUN_ID"',
        '"exact_main_ci_attempt=$CI_RUN_ATTEMPT"',
        "'dynamic_stdout_included=false'",
        "'wall_clock_timing_included=false'",
        "'benchmark_measurements_included=false'",
    ):
        if marker not in verify_gates_run:
            raise ContractError(
                "active RC public verifier must run the complete Linux gates and emit only the canonical summary"
            )

    verify_rebuild_step = parsed_verify_steps[7]
    require_yaml_scalar(
        verify_rebuild_step.get("run"),
        "./scripts/round6-rc-artifacts.sh",
        source,
        "jobs.verify_published.steps[7].run",
    )
    verify_rebuild_env = yaml_mapping(
        verify_rebuild_step.get("env"),
        source,
        "jobs.verify_published.steps[7].env",
    )
    for key, expected in (
        ("RELEASE_RC_BUILD", "1"),
        ("RELEASE_RC_TAG", "${{ inputs.tag }}"),
        ("RELEASE_RC_EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("RELEASE_RC_EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("RC_TEST_SUMMARY_INPUT", "${{ runner.temp }}/rc-release-test-summary.txt"),
        ("RC_PUBLISH_RELEASE", "true"),
        ("RC_HOST_EVIDENCE_INPUT", "${{ runner.temp }}/round8-host-evidence.json"),
        (
            "RC_HOST_EVIDENCE_SIDECAR_INPUT",
            "${{ runner.temp }}/round8-host-evidence.json.sha256",
        ),
        ("RC_RUNNER_LABEL", "ubuntu-24.04"),
        ("RC_RUNNER_NAME", RC_REPRODUCIBLE_RUNNER_NAME),
        ("RC_RUNNER_IMAGE_OS", "UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER"),
        ("RC_RUNNER_IMAGE_VERSION", "UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER"),
        ("ROUND6_SAFE_SPARSE_BUILD", "1"),
        ("REQUIRE_DIST_ARTIFACTS", "1"),
    ):
        require_yaml_scalar(
            verify_rebuild_env.get(key),
            expected,
            source,
            f"jobs.verify_published.steps[7].env.{key}",
        )

    verify_compare_run = yaml_scalar(
        parsed_verify_steps[8].get("run"),
        source,
        "jobs.verify_published.steps[8].run",
    )
    for marker in (
        'actual_local="$(find dist -mindepth 1 -maxdepth 1 -printf \'%f\\n\' | LC_ALL=C sort)"',
        'actual_published="$(find "$published" -mindepth 1 -maxdepth 1 -printf \'%f\\n\' | LC_ALL=C sort)"',
        'cmp -s "dist/$name" "$published/$name"',
        'ordinary_assets="$(grep -Fvx',
        '-e round8-host-evidence.json.sha256 <<<"$expected")"',
        '[[ "$(grep -c . <<<"$ordinary_assets")" == 17 ]]',
        'done <<<"$ordinary_assets"',
        "for name in round8-host-evidence.json round8-host-evidence.json.sha256; do",
        '[[ "$latest_tag" == v0.15 ]]',
        '[[ "$(jq -r \'.object.sha\' <<<"$main_ref")" == "$EXPECTED_COMMIT" ]]',
        '[[ "$(jq -r \'.object.sha\' <<<"$tag_ref")" == "$EXPECTED_TAG_OBJECT" ]]',
        '[[ "$(jq -r \'.tree.sha\' <<<"$commit_object")" == "$EXPECTED_TREE" ]]',
        'cmp -s "$RUNNER_TEMP/rc-public-release-fingerprint.json"',
        "immutable public RC rebuilt and byte-compared read-only; no remote state mutation executed",
    ):
        if marker not in verify_compare_run:
            raise ContractError(
                "active RC public verifier must byte-compare all assets and recheck the immutable release identity"
            )
    ordinary_public_attestation = re.compile(
        r'(?m)^\s*if gh attestation verify "\$published/\$name" \\\n'
        r'\s*--repo "\$GITHUB_REPOSITORY" \\\n'
        r'\s*--signer-workflow "\$GITHUB_REPOSITORY/\.github/workflows/release-rc\.yml" \\\n'
        r'\s*--signer-digest "\$EXPECTED_COMMIT" \\\n'
        r'\s*--source-ref "refs/tags/\$TAG" \\\n'
        r'\s*--source-digest "\$EXPECTED_COMMIT" >/dev/null; then$'
    )
    host_public_attestation = re.compile(
        r'(?m)^\s*if gh attestation verify "\$published/\$name" \\\n'
        r'\s*--repo "\$GITHUB_REPOSITORY" \\\n'
        r'\s*--signer-workflow "\$GITHUB_REPOSITORY/\.github/workflows/round8-host-validation\.yml" \\\n'
        r'\s*--signer-digest "\$EXPECTED_COMMIT" \\\n'
        r'\s*--source-ref "refs/tags/\$TAG" \\\n'
        r'\s*--source-digest "\$EXPECTED_COMMIT" >/dev/null; then$'
    )
    if (
        len(ordinary_public_attestation.findall(verify_compare_run)) != 1
        or len(host_public_attestation.findall(verify_compare_run)) != 1
        or verify_compare_run.count("gh attestation verify") != 2
    ):
        raise ContractError(
            "active RC public verifier must bind 17 ordinary assets to the release workflow and Host evidence to the protected Host workflow"
        )

    verify_run_texts = tuple(
        yaml_scalar(
            run_node,
            source,
            f"jobs.verify_published.steps[{index}].run",
        )
        for index, step in enumerate(parsed_verify_steps)
        for run_node in (step.get("run"),)
        if run_node is not None
    )
    if (
        re.search(
            r"(?im)(?:gh\s+release\s+(?:create|edit|upload|delete)|"
            r"actions/(?:upload-artifact|attest-build-provenance|cache)@|"
            r"gh\s+attestation\s+(?!verify\b)|"
            r"git\s+push\b|cache:\s*true\b)",
            verify_published_text,
        )
        or any(
            read_only_gh_api_mutation_reason(run_text) is not None
            for run_text in verify_run_texts
        )
    ):
        raise ContractError(
            "active RC public verifier must not mutate Releases, artifacts, attestations, caches, tags, or repository state"
        )

    required = (
        "RC release v0.16-rc.2 - Linux sandbox validation",
        "expected_tag_object_sha:",
        "ci_run:",
        "publish_rc_release:",
        "host_run:",
        "host_artifact_id:",
        "host_artifact_digest:",
        "host_challenge:",
        "round8-rc-publication",
        ".github/workflows/round8-host-validation.yml",
        "--signer-workflow",
        "--source-ref",
        "--source-digest",
        "--signer-digest",
        ".execution.challenge == $challenge",
        ".execution.workflow.run_id == $run_id",
        ".id == $artifact_id and .digest == $digest and .expired == false and",
        '[[ "$TAG" == v0.16-rc.2 ]]',
        '[[ "$tag_object_sha" == "$EXPECTED_TAG_OBJECT" ]]',
        '[[ "$(git rev-parse "$TAG^{tag}")" == "$EXPECTED_TAG_OBJECT" ]]',
        "Bind RC admission to successful exact-main push CI",
        "Run complete Linux RC verification gates and capture summary",
        "rc_gate.safe_contract=PASS",
        "rc_gate.full_linux_quality=PASS",
        f"rc_gate.cpa_{CPA_ROUND8_VERSION}_primary_source_compatibility=PASS",
        "rc_gate.rc_integration=PASS",
        "rc_gate.clean_tree=PASS",
        ".run_attempt == $run_attempt",
        "Build and reproduce exact RC release assets",
        "RC_TEST_SUMMARY_INPUT:",
        CPA_ROUND8_VERSION,
        CPA_ROUND8_COMMIT,
        RC_BUILDER_IMAGE,
        RC_BUILDER_IMAGE_DIGEST,
        RC_BUILDER_REFERENCE,
        RC_PROVENANCE_ACTION,
        "RC_INTERNAL_GATES_PASS / PRIVATE_HOST_TEST_CANDIDATE / HOST_VALIDATION_REQUIRED / INDEPENDENT_AUDIT_REQUIRED / PRODUCTION_NOT_APPROVED / NOT_STABLE_V0.16",
        "RC_INTERNAL_GATES_PASS / HOST_EVIDENCE_ATTESTED_PROTECTED_WORKFLOW / SANDBOX_IDENTITY_AND_LOCALITY_VERIFIED / REAL_PROVIDER_NOT_CONTACTED / PRODUCTION_NOT_ACCESSED / INDEPENDENT_AUDIT_REQUIRED / PRODUCTION_NOT_APPROVED / NOT_STABLE_V0.16",
        "cyber-abuse-guard-v0.16-rc.2.so",
        "cyber-abuse-guard_0.16-rc.2_linux_amd64.zip",
        "cyber-abuse-guard-v0.16-rc.2-audit-bundle.zip",
        "rc-release-test-summary.txt.sha256",
        "rc-release-evidence.md.sha256",
        "cyber-abuse-guard-v0.16-rc.2-source.tar.gz.sha256",
        "rc-release-manifest.json.sha256",
        "Create, byte-check, and publish v0.16-rc.2 prerelease",
        "v0.16-rc.2 - independent audit and Linux sandbox validation required",
        ".assets | length == 19",
        "--draft",
        "--prerelease",
        "--latest=false",
        '"repos/${GITHUB_REPOSITORY}/releases/latest"',
    )
    for marker in required:
        if marker not in text:
            raise ContractError(f"active RC workflow is missing reviewed marker: {marker}")
    if text.count(
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/round8-host-validation.yml"'
    ) != 3:
        raise ContractError(
            "active RC workflow must verify the protected Host signer in ingestion, publication, and public read-only verification"
        )
    if text.count(
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release-rc.yml"'
    ) != 2:
        raise ContractError(
            "active RC workflow must bind ordinary assets to the exact release workflow in publication and public verification"
        )
    for marker in (
        '--signer-digest "$EXPECTED_COMMIT"',
        '--source-ref "refs/tags/$TAG"',
        '--source-digest "$EXPECTED_COMMIT"',
    ):
        if text.count(marker) != 5:
            raise ContractError(
                "active RC workflow must bind all five reviewed attestation checks to the exact tag and commit"
            )
    if text.count("contents: write") != 1:
        raise ContractError("active RC workflow must grant contents: write only in publish")
    if re.search(r"(?im)runs-on:\s*(?:windows|macos)", text):
        raise ContractError("active RC workflow must remain Linux only")
    if "round6-prerelease-attestation.json" in text or "formal-release-attestation.json" in text:
        raise ContractError("active RC workflow may not emit formal evidence assets")
    if "release-evidence-final.md" in text or "FORMAL_GATES_PASS" in text:
        raise ContractError("active RC workflow may not claim formal release evidence")
    for current_identity in (CPA_CURRENT_VERSION, CPA_CURRENT_COMMIT):
        if current_identity in text:
            raise ContractError(
                "active RC workflow must retain the immutable Round 8 CPA identity"
            )


def validate_round9_independent_audit_reviewed_script(
    text: str, source: Path
) -> None:
    matches = tuple(
        relative
        for relative in ROUND9_INDEPENDENT_AUDIT_REVIEWED_SCRIPT_SHA256
        if tuple(source.parts[-len(Path(relative).parts) :]) == Path(relative).parts
    )
    if len(matches) != 1:
        raise ContractError(
            f"Round 9 independent-audit verifier is outside the reviewed path: {source}"
        )
    relative = matches[0]
    expected = ROUND9_INDEPENDENT_AUDIT_REVIEWED_SCRIPT_SHA256[relative]
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != expected:
        raise ContractError(
            f"Round 9 independent-audit verifier differs from reviewed contract: {relative}"
        )


def validate_round9_gate_workflow(text: str, source: Path) -> None:
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != ROUND9_GATE_WORKFLOW_SHA256:
        raise ContractError("policy and corpus gate workflow differs from reviewed text")
    validate_workflow_safety(text, source)
    document = parse_workflow_yaml(text, source)
    root = require_yaml_keys(
        document,
        ("name", "on", "permissions", "concurrency", "env", "jobs"),
        source,
        "workflow",
    )
    require_yaml_scalar(root.get("name"), "Policy and Corpus Gate", source, "name")
    require_yaml_keys(root.get("on"), ("push", "pull_request"), source, "on")
    permissions = require_yaml_keys(
        root.get("permissions"), ("contents",), source, "permissions"
    )
    require_yaml_scalar(permissions["contents"], "read", source, "permissions.contents")
    env = require_yaml_keys(
        root.get("env"),
        (
            "GOTOOLCHAIN",
            "GOFLAGS",
            "GO_VERSION",
            "ROUND9_BENIGN_MANIFEST_SHA256",
            "ROUND9_BENIGN_CASES_SHA256",
            "ROUND9_PAIRED_MANIFEST_SHA256",
            "ROUND9_PAIRED_CASES_SHA256",
            "ROUND9_PAIRED_LABEL_AUDIT_SHA256",
        ),
        source,
        "env",
    )
    for name, expected in (
        ("GOTOOLCHAIN", "go1.26.4"),
        ("GOFLAGS", "-mod=readonly"),
        ("GO_VERSION", "1.26.4"),
        (
            "ROUND9_BENIGN_MANIFEST_SHA256",
            "d33e4ff8954741a2fe9c24c0d34b239c649c7e0a6d31463cddba84dc6b6580b8",
        ),
        (
            "ROUND9_BENIGN_CASES_SHA256",
            "36d7f4dd635710f7ee81d02f9f62502c6276e554c80fc852f3d40acbfa70688d",
        ),
        (
            "ROUND9_PAIRED_MANIFEST_SHA256",
            "29d84900edeec8fceceee9ccd2640571f1e962643931f388dcc842b058c6a2c2",
        ),
        (
            "ROUND9_PAIRED_CASES_SHA256",
            "2a30da8d4872029d9b070a7b8bd8fb72a132994a21975f64b49cd56ecf4b2b3d",
        ),
        (
            "ROUND9_PAIRED_LABEL_AUDIT_SHA256",
            "a2d34853f20ae1c0b18690a4f58f100fe0014c53232457d5084aa90407e2ab8f",
        ),
    ):
        require_yaml_scalar(env[name], expected, source, f"env.{name}")
    require_yaml_keys(
        root.get("jobs"), ("round9-policy-and-corpus",), source, "jobs"
    )
    for marker in (
        "python3 -B scripts/round6_safe_gate_contract.py --root .",
        "python3 -B scripts/round9_external_evaluation_contract_test.py",
        "python3 -B tools/round9-eval/round9_eval_core_test.py",
        "python3 -B tools/round9-eval/cag_round9_external_evaluator_test.py",
        "python3 -B tools/round9-eval/cag_round9_cpa_sandbox_adapter_test.py",
        "python3 -B tools/round9-eval/cag_round9_eval_broker_test.py",
        "bash -n tools/round9-eval/install.sh",
        "make round9-fuzz",
        "make round9-corpus-contract",
        "make round9-public-corpus",
        "TestClassifierPolicyIdentity",
        "TestClassifierPolicySourceInventoryClosure",
        'classifier_policy_sha256=${classifier_policy_sha256}',
        "test ! -e testdata/round9-independent-benign-v1/cases.jsonl",
        "test ! -e testdata/round9-independent-malicious-v1",
        "independent_corpus_executed=false",
        "classifier-policy-v9",
        "1.0.10",
    ):
        if marker not in text:
            raise ContractError(f"Round 9 policy gate is missing reviewed marker: {marker}")
    if "round9-host-evidence" in text:
        raise ContractError("Round 9 policy gate must not depend on the retired Host sidecar")


def validate_round9_host_workflow(text: str, source: Path) -> None:
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != ROUND9_HOST_WORKFLOW_SHA256:
        raise ContractError("Round 9 Host workflow differs from reviewed text")
    reject_workflow_yaml_indirection(text, source)
    document = parse_workflow_yaml(text, source)
    root = require_yaml_keys(
        document,
        ("name", "on", "permissions", "concurrency", "jobs"),
        source,
        "workflow",
    )
    require_yaml_scalar(
        root.get("name"), "Round 9 protected CPA Host validation", source, "name"
    )
    on = require_yaml_keys(root.get("on"), ("workflow_dispatch",), source, "on")
    dispatch = require_yaml_keys(
        on.get("workflow_dispatch"), ("inputs",), source, "on.workflow_dispatch"
    )
    inputs = require_yaml_keys(
        dispatch["inputs"], ROUND9_HOST_INPUT_ORDER, source, "on.workflow_dispatch.inputs"
    )
    for input_name, input_node in inputs.items():
        path = f"on.workflow_dispatch.inputs.{input_name}"
        values = require_yaml_keys(
            input_node, ("description", "required", "type"), source, path
        )
        require_yaml_scalar(values["required"], "true", source, f"{path}.required")
        require_yaml_scalar(values["type"], "string", source, f"{path}.type")
    permissions = require_yaml_keys(
        root.get("permissions"),
        ("actions", "attestations", "contents", "id-token"),
        source,
        "permissions",
    )
    for permission, expected in (
        ("actions", "read"),
        ("attestations", "write"),
        ("contents", "read"),
        ("id-token", "write"),
    ):
        require_yaml_scalar(
            permissions[permission], expected, source, f"permissions.{permission}"
        )
    concurrency = require_yaml_keys(
        root.get("concurrency"), ("group", "cancel-in-progress"), source, "concurrency"
    )
    require_yaml_scalar(
        concurrency["group"],
        "round9-external-evaluation-${{ inputs.tag }}",
        source,
        "concurrency.group",
    )
    require_yaml_scalar(
        concurrency["cancel-in-progress"],
        "false",
        source,
        "concurrency.cancel-in-progress",
    )
    jobs = require_yaml_keys(root.get("jobs"), ("external-evaluation",), source, "jobs")
    host_job = yaml_mapping(
        jobs["external-evaluation"], source, "jobs.external-evaluation"
    )
    environment = require_yaml_keys(
        host_job.get("environment"), ("name",), source, "jobs.external-evaluation.environment"
    )
    require_yaml_scalar(
        environment["name"],
        "round9-host-validation",
        source,
        "jobs.external-evaluation.environment.name",
    )
    runner_labels = tuple(
        yaml_scalar(node, source, f"jobs.external-evaluation.runs-on[{index}]")
        for index, node in enumerate(
            yaml_sequence(
                host_job.get("runs-on"), source, "jobs.external-evaluation.runs-on"
            )
        )
    )
    if runner_labels != ("self-hosted", "linux", "x64", "cag-round9-sandbox"):
        raise ContractError("Round 9 Host workflow runner labels changed")
    steps = yaml_sequence(
        host_job.get("steps"), source, "jobs.external-evaluation.steps"
    )
    if len(steps) != 3:
        raise ContractError("Round 9 Host workflow must contain exactly three reviewed steps")
    parsed_steps = [
        yaml_mapping(step, source, f"jobs.external-evaluation.steps[{index}]")
        for index, step in enumerate(steps)
    ]
    broker_env = yaml_mapping(
        parsed_steps[0].get("env"),
        source,
        "jobs.external-evaluation.steps[0].env",
    )
    for name, expected in (
        ("DISPATCH_REF", "${{ github.ref }}"),
        ("DISPATCH_SHA", "${{ github.sha }}"),
        ("WORKFLOW_REF", "${{ github.workflow_ref }}"),
        ("WORKFLOW_SHA", "${{ github.workflow_sha }}"),
    ):
        require_yaml_scalar(
            broker_env.get(name),
            expected,
            source,
            f"jobs.external-evaluation.steps[0].env.{name}",
        )
    broker_run = yaml_scalar(
        parsed_steps[0].get("run"),
        source,
        "jobs.external-evaluation.steps[0].run",
    )
    if "actions/checkout@" in text or "sparse-checkout" in text:
        raise ContractError("Round 9 external Host workflow must not checkout candidate source")
    if len(re.findall(r"(?m)^\s+run:\s*\|\s*$", text)) != 1:
        raise ContractError("Round 9 Host workflow must have one fixed shell entry point")
    for marker in (
        "sudo -n -- /usr/local/libexec/cag-round9-eval-broker evaluate",
        '--candidate-identity "$CANDIDATE_IDENTITY"',
        '--workflow-run-id "$WORKFLOW_RUN_ID"',
        '--workflow-run-attempt "$WORKFLOW_RUN_ATTEMPT"',
        '[[ "$DISPATCH_REF" == "refs/tags/$TAG" ]]',
        '[[ "$DISPATCH_SHA" == "$COMMIT" ]]',
        '[[ "$WORKFLOW_REF" == "${REPOSITORY}/.github/workflows/round9-host-validation.yml@refs/tags/$TAG" ]]',
        '[[ "$WORKFLOW_SHA" == "$COMMIT" ]]',
        '--dispatch-ref "$DISPATCH_REF"',
        '--dispatch-sha "$DISPATCH_SHA"',
        '--workflow-ref "$WORKFLOW_REF"',
        '--workflow-sha "$WORKFLOW_SHA"',
        "round9-external-evaluation.json",
        "round9-external-ledger-proof.json",
        "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "retention-days: 30",
    ):
        if marker not in text:
            raise ContractError(f"Round 9 Host workflow is missing reviewed marker: {marker}")
    if text.count("round9-external-evaluation.json") != 2:
        raise ContractError("Round 9 Host workflow must attest and upload one evaluation file")
    if text.count("round9-external-ledger-proof.json") != 2:
        raise ContractError("Round 9 Host workflow must attest and upload one ledger proof")
    public_output_root = (
        "/var/lib/cag-round9-eval-broker/public/"
        "${{ github.run_id }}-${{ github.run_attempt }}"
    )
    if text.count(public_output_root) != 5:
        raise ContractError("Round 9 Host workflow public output root changed")
    for forbidden in (
        "${{ secrets.",
        "${{ github.token }}",
        "contents: write",
        "git checkout",
        "round9-host-evidence",
    ):
        if forbidden in text:
            raise ContractError(
                f"Round 9 Host workflow contains forbidden candidate-controlled execution: {forbidden}"
            )
    for forbidden_command in (
        "python3 ",
        "jq ",
        "bash ",
        "sh ",
        "docker ",
        "curl ",
        "wget ",
    ):
        if forbidden_command in broker_run:
            raise ContractError(
                "Round 9 Host broker step contains a forbidden alternate execution path: "
                + forbidden_command
            )
    if re.search(r"(?im)runs-on:\s*(?:windows|macos)", text):
        raise ContractError(
            "Round 9 Host workflow must remain Linux-only and content read-only"
        )


def validate_round9_rc_workflow(text: str, source: Path) -> None:
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != ROUND9_RC_WORKFLOW_SHA256:
        raise ContractError("Round 9 RC workflow differs from reviewed text")
    reject_workflow_yaml_indirection(text, source)
    document = parse_workflow_yaml(text, source)
    root = require_yaml_keys(
        document,
        ("name", "on", "permissions", "concurrency", "env", "jobs"),
        source,
        "workflow",
    )
    require_yaml_scalar(
        root.get("name"),
        "Round 9 RC release v0.16-rc.4 - Linux counted-Mock admission",
        source,
        "name",
    )
    on = require_yaml_keys(root.get("on"), ("workflow_dispatch",), source, "on")
    dispatch = require_yaml_keys(
        on.get("workflow_dispatch"), ("inputs",), source, "on.workflow_dispatch"
    )
    inputs = require_yaml_keys(
        dispatch["inputs"], ROUND9_RC_INPUT_ORDER, source, "on.workflow_dispatch.inputs"
    )
    if len(inputs) != REPOSITORY_WORKFLOW_DISPATCH_INPUT_LIMIT:
        raise ContractError("Round 9 RC workflow must use the exact ten reviewed inputs")
    for input_name, input_node in inputs.items():
        path = f"on.workflow_dispatch.inputs.{input_name}"
        values = require_yaml_keys(
            input_node, ("description", "required", "type"), source, path
        )
        if not yaml_scalar(values["description"], source, f"{path}.description").strip():
            raise ContractError(f"workflow {path}.description may not be empty")
        required = "false" if input_name in {
            "host_run",
            "host_artifact_id",
            "host_artifact_digest",
            "host_challenge",
        } else "true"
        require_yaml_scalar(
            values["required"],
            required,
            source,
            f"{path}.required",
            tag="tag:yaml.org,2002:bool",
        )
        require_yaml_scalar(values["type"], "string", source, f"{path}.type")
    permissions = require_yaml_keys(
        root.get("permissions"), ("actions", "contents"), source, "permissions"
    )
    require_yaml_scalar(permissions["actions"], "read", source, "permissions.actions")
    require_yaml_scalar(permissions["contents"], "read", source, "permissions.contents")
    env = require_yaml_keys(
        root.get("env"),
        (
            "GOTOOLCHAIN",
            "GOFLAGS",
            "GO_VERSION",
            "VERSION",
            "RC_VERSION",
            "CYCLONEDX_GOMOD_VERSION",
            "GOVULNCHECK_VERSION",
            "GH_CLI_VERSION",
            "GH_CLI_LINUX_AMD64_SHA256",
            "RC_BUILDER_IMAGE",
            "RC_BUILDER_IMAGE_DIGEST",
            "RC_BUILDER_REFERENCE",
            "ROUND9_NEW_PUBLIC_PRERELEASE_CREATION",
        ),
        source,
        "env",
    )
    for key, expected in (
        ("GOTOOLCHAIN", "go1.26.4"),
        ("GOFLAGS", "-mod=readonly"),
        ("GO_VERSION", "1.26.4"),
        ("VERSION", "0.16"),
        ("RC_VERSION", "0.16-rc.4"),
        (
            "ROUND9_NEW_PUBLIC_PRERELEASE_CREATION",
            "BLOCKED_PENDING_EXACT_CANDIDATE_INDEPENDENT_AUDIT_GATE",
        ),
    ):
        require_yaml_scalar(env[key], expected, source, f"env.{key}")
    jobs = require_yaml_keys(
        root.get("jobs"),
        ("admission", "build", "publish", "publication_blocked", "verify_published"),
        source,
        "jobs",
    )
    admission = require_yaml_keys(
        jobs["admission"],
        ("runs-on", "timeout-minutes", "outputs", "steps"),
        source,
        "jobs.admission",
    )
    admission_outputs = exact_string_mapping(
        admission["outputs"], source, "jobs.admission.outputs"
    )
    if admission_outputs != (
        ("ci_run_id", "${{ steps.admit.outputs.ci_run_id }}"),
        ("ci_run_attempt", "${{ steps.admit.outputs.ci_run_attempt }}"),
        ("round9_gate_run_id", "${{ steps.admit.outputs.round9_gate_run_id }}"),
        (
            "round9_gate_run_attempt",
            "${{ steps.admit.outputs.round9_gate_run_attempt }}",
        ),
        ("host_run_id", "${{ steps.admit.outputs.host_run_id }}"),
        ("host_run_attempt", "${{ steps.admit.outputs.host_run_attempt }}"),
        (
            "publication_permitted",
            "${{ steps.admit.outputs.publication_permitted }}",
        ),
    ):
        raise ContractError("Round 9 RC admission outputs differ from reviewed run identities")
    admission_steps = yaml_sequence(
        admission["steps"], source, "jobs.admission.steps"
    )
    if len(admission_steps) != 1:
        raise ContractError("Round 9 RC admission must contain one fail-closed step")
    admission_step = yaml_mapping(
        admission_steps[0], source, "jobs.admission.steps[0]"
    )
    require_yaml_scalar(
        admission_step.get("id"), "admit", source, "jobs.admission.steps[0].id"
    )
    admission_run = yaml_scalar(
        admission_step.get("run"), source, "jobs.admission.steps[0].run"
    )
    for marker in (
        '[[ "$ROUND9_GATE_RUN" =~ ^([1-9][0-9]*):([1-9][0-9]*)$ ]]',
        'round9_gate="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${ROUND9_GATE_RUN_ID}")"',
        '.name == "Round 9 policy gate"',
        '.path == ".github/workflows/round9-gate.yml"',
        '.event == "push" and .head_branch == "main"',
        '.head_sha == $commit and .status == "completed" and',
        '.conclusion == "success" and .repository.full_name == $repo',
        'main_ref="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"',
        'tag_ref="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${TAG}")"',
        'tag_object="$(gh api "repos/${GITHUB_REPOSITORY}/git/tags/${EXPECTED_TAG_OBJECT}")"',
        'commit_object="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${EXPECTED_COMMIT}")"',
        "historical_repository='yujianwudi/cyber-abuse-guard'",
        '"repos/${historical_repository}/git/ref/tags/v0.16-rc.2"',
        '"repos/${historical_repository}/git/tags/58bd9b78886da04c03b2c6d8f28e8cd7f2436e84"',
        '"repos/${historical_repository}/git/commits/9665fdd1aacab0d79b8790d68c87c6c8c80f8911"',
        '"repos/${historical_repository}/actions/workflows/315644586"',
        '.id == 315644586 and',
        '.path == ".github/workflows/release-rc.yml" and',
        '.state == "disabled_manually"',
        '"repos/${historical_repository}/actions/workflows/318443961"',
        '.id == 318443961 and',
        '.path == ".github/workflows/round8-host-validation.yml" and',
        '"repos/${historical_repository}/releases?per_page=100"',
        'jq -e \'[.[][] | select(.tag_name == "v0.16-rc.2")] | length == 0\'',
        '"repos/${GITHUB_REPOSITORY}/releases?per_page=100"',
        'jq -e --arg tag "$TAG" \'',
        '[.[][] | select(.tag_name == $tag)] | length == 0',
        'an existing Round 9 Release is fail-only until exact-candidate independent-audit evidence passes mechanical verification',
        '[[ -z "$HOST_RUN_ID" && -z "$HOST_RUN_ATTEMPT" ]]',
        '[[ -z "$HOST_ARTIFACT_ID" && -z "$HOST_ARTIFACT_DIGEST" && -z "$HOST_CHALLENGE" ]]',
        "printf 'publication_permitted=false\\n'",
    ):
        if marker not in admission_run:
            raise ContractError(
                f"Round 9 RC admission is missing reviewed fail-only marker: {marker}"
            )
    if admission_run.count('.state == "disabled_manually"') != 2:
        raise ContractError(
            "Round 9 RC admission must require both historical workflow IDs to be manually disabled"
        )
    if admission_run.count("repos/${historical_repository}/") != 6:
        raise ContractError(
            "Round 9 RC admission must bind every Round 8 identity to the predecessor repository"
        )
    for forbidden in (
        'repos/${GITHUB_REPOSITORY}/git/ref/tags/v0.16-rc.2',
        'repos/${GITHUB_REPOSITORY}/git/tags/58bd9b78886da04c03b2c6d8f28e8cd7f2436e84',
        'repos/${GITHUB_REPOSITORY}/git/commits/9665fdd1aacab0d79b8790d68c87c6c8c80f8911',
        'repos/${GITHUB_REPOSITORY}/actions/workflows/315644586',
        'repos/${GITHUB_REPOSITORY}/actions/workflows/318443961',
    ):
        if forbidden in admission_run:
            raise ContractError(
                "Round 9 RC admission resolves a historical identity from the current repository"
            )
    if (
        admission_run.count("printf 'publication_permitted=false\\n'") != 1
        or "publication_permitted=true" in admission_run
    ):
        raise ContractError(
            "Round 9 RC admission must keep new publication mechanically disabled"
        )
    for forbidden in (
        "already_public",
        "inputs.publish_rc_release",
        "PUBLISH_RC_RELEASE",
    ):
        if forbidden in text:
            raise ContractError(
                f"Round 9 RC workflow retains retired public-recovery input or state: {forbidden}"
            )

    for job_name in ("build", "publish"):
        job = yaml_mapping(jobs[job_name], source, f"jobs.{job_name}")
        defaults = require_yaml_keys(
            job.get("defaults"), ("run",), source, f"jobs.{job_name}.defaults"
        )
        run_defaults = require_yaml_keys(
            defaults["run"],
            ("shell",),
            source,
            f"jobs.{job_name}.defaults.run",
        )
        require_yaml_scalar(
            run_defaults["shell"],
            "bash",
            source,
            f"jobs.{job_name}.defaults.run.shell",
        )
        for step_index, step_node in enumerate(
            yaml_sequence(job.get("steps"), source, f"jobs.{job_name}.steps")
        ):
            step = yaml_mapping(
                step_node, source, f"jobs.{job_name}.steps[{step_index}]"
            )
            if "continue-on-error" in step:
                raise ContractError(
                    f"Round 9 RC {job_name} steps may not define continue-on-error"
                )

    publish = require_yaml_keys(
        jobs["publish"],
        (
            "needs",
            "if",
            "environment",
            "runs-on",
            "container",
            "defaults",
            "timeout-minutes",
            "permissions",
            "steps",
        ),
        source,
        "jobs.publish",
    )
    publish_needs = tuple(
        yaml_scalar(node, source, f"jobs.publish.needs[{index}]")
        for index, node in enumerate(
            yaml_sequence(publish["needs"], source, "jobs.publish.needs")
        )
    )
    if publish_needs != ("admission", "build"):
        raise ContractError("Round 9 RC publish dependencies differ from reviewed order")
    require_yaml_scalar(
        publish["if"],
        "${{ needs.admission.outputs.publication_permitted == 'true' }}",
        source,
        "jobs.publish.if",
    )
    publish_environment = require_yaml_keys(
        publish["environment"], ("name",), source, "jobs.publish.environment"
    )
    require_yaml_scalar(
        publish_environment["name"],
        "round9-rc-publication",
        source,
        "jobs.publish.environment.name",
    )
    publish_permissions = require_yaml_keys(
        publish["permissions"],
        ("actions", "attestations", "contents", "id-token"),
        source,
        "jobs.publish.permissions",
    )
    for permission, expected in (
        ("actions", "read"),
        ("attestations", "write"),
        ("contents", "read"),
        ("id-token", "write"),
    ):
        require_yaml_scalar(
            publish_permissions[permission],
            expected,
            source,
            f"jobs.publish.permissions.{permission}",
        )

    publish_steps = yaml_sequence(publish["steps"], source, "jobs.publish.steps")
    expected_publish_step_names = (
        "Install exact Safe Gate runtime before checkout",
        "Checkout exact Round 9 tag with restricted data excluded",
        "Run exact Safe Gate after restricted checkout",
        "Recheck Round 9 external-evaluation and independent-audit contracts",
        "Install bounded publication dependencies",
        "Download, attest, and verify signed external evaluation and ledger",
        "Write canonical Round 9 publication summary",
        "Rebuild reproducible 19-asset Round 9 publication candidate",
        "Verify Round 9 publication manifest and exact allowlist",
        "Attest exact Round 9 release-built assets",
        "Verify exact-candidate independent-audit package or report NOT_PROVIDED",
    )
    if len(publish_steps) != len(expected_publish_step_names):
        raise ContractError(
            "Round 9 RC publish job must retain the exact eleven reviewed steps"
        )
    parsed_publish_steps: list[dict[str, Node]] = []
    for index, (step_node, expected_name) in enumerate(
        zip(publish_steps, expected_publish_step_names)
    ):
        step = yaml_mapping(step_node, source, f"jobs.publish.steps[{index}]")
        require_yaml_scalar(
            step.get("name"),
            expected_name,
            source,
            f"jobs.publish.steps[{index}].name",
        )
        if "if" in step or "continue-on-error" in step:
            raise ContractError(
                "Round 9 RC publish steps must be unconditional and fail closed"
            )
        parsed_publish_steps.append(step)

    audit_step = parsed_publish_steps[-1]
    audit_env = exact_string_mapping(
        audit_step.get("env"), source, "jobs.publish.steps[10].env"
    )
    expected_audit_env = (
        ("EXPECTED_TAG_OBJECT", "${{ inputs.expected_tag_object_sha }}"),
        ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
        ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ("AUDIT_REPOSITORY", "${{ vars.ROUND9_INDEPENDENT_AUDITOR_REPOSITORY }}"),
        (
            "AUDIT_WORKFLOW_NAME",
            "${{ vars.ROUND9_INDEPENDENT_AUDITOR_WORKFLOW_NAME }}",
        ),
        ("AUDIT_WORKFLOW", "${{ vars.ROUND9_INDEPENDENT_AUDITOR_WORKFLOW }}"),
        ("AUDIT_REF", "${{ vars.ROUND9_INDEPENDENT_AUDITOR_REF }}"),
        (
            "AUDIT_WORKFLOW_SHA",
            "${{ vars.ROUND9_INDEPENDENT_AUDITOR_WORKFLOW_SHA }}",
        ),
        ("AUDIT_RUN_ID", "${{ vars.ROUND9_INDEPENDENT_AUDIT_RUN_ID }}"),
        (
            "AUDIT_RUN_ATTEMPT",
            "${{ vars.ROUND9_INDEPENDENT_AUDIT_RUN_ATTEMPT }}",
        ),
        (
            "AUDIT_ARTIFACT_ID",
            "${{ vars.ROUND9_INDEPENDENT_AUDIT_ARTIFACT_ID }}",
        ),
        (
            "AUDIT_ARTIFACT_NAME",
            "${{ vars.ROUND9_INDEPENDENT_AUDIT_ARTIFACT_NAME }}",
        ),
        (
            "AUDIT_ARTIFACT_DIGEST",
            "${{ vars.ROUND9_INDEPENDENT_AUDIT_ARTIFACT_DIGEST }}",
        ),
        ("AUDIT_CHALLENGE", "${{ vars.ROUND9_INDEPENDENT_AUDIT_CHALLENGE }}"),
        (
            "AUDIT_PUBLIC_KEY_BASE64",
            "${{ vars.ROUND9_INDEPENDENT_AUDITOR_PUBLIC_KEY_BASE64 }}",
        ),
        (
            "AUDIT_PUBLIC_KEY_SHA256",
            "${{ vars.ROUND9_INDEPENDENT_AUDITOR_PUBLIC_KEY_SHA256 }}",
        ),
        ("AUDIT_KEY_ID", "${{ vars.ROUND9_INDEPENDENT_AUDITOR_KEY_ID }}"),
        (
            "HOST_EVALUATOR_PUBLIC_KEY_SHA256",
            "${{ vars.ROUND9_EVALUATOR_PUBLIC_KEY_SHA256 }}",
        ),
        (
            "AUDIT_LEDGER_RULESET_ID",
            "${{ vars.ROUND9_INDEPENDENT_AUDIT_LEDGER_RULESET_ID }}",
        ),
        (
            "AUDIT_LEDGER_RULESET_NAME",
            "${{ vars.ROUND9_INDEPENDENT_AUDIT_LEDGER_RULESET_NAME }}",
        ),
        (
            "GH_TOKEN",
            "${{ secrets.ROUND9_INDEPENDENT_AUDIT_REMOTE_VERIFY_TOKEN }}",
        ),
    )
    if audit_env != expected_audit_env:
        raise ContractError(
            "Round 9 independent-audit step trust anchors differ from reviewed configuration"
        )
    audit_run = yaml_scalar(
        audit_step.get("run"), source, "jobs.publish.steps[10].run"
    )
    audit_markers = (
        "set -euo pipefail",
        'missing=false',
        'if [[ "$missing" == true ]]; then',
        'artifact="$(gh api "repos/${AUDIT_REPOSITORY}/actions/artifacts/${AUDIT_ARTIFACT_ID}")"',
        '.id == $id and .name == $name and .digest == $digest and',
        '.expired == false and .workflow_run.id == $run and',
        '"repos/${AUDIT_REPOSITORY}/actions/artifacts/${AUDIT_ARTIFACT_ID}/zip" >"$archive"',
        '[[ "sha256:$(sha256sum "$archive" | awk \'{print $1}\')" == "$AUDIT_ARTIFACT_DIGEST" ]]',
        '"round9-independent-audit.json",',
        '"round9-independent-audit-ledger-proof.json",',
        'if len(infos) != 2 or set(names) != expected or len(names) != len(set(names)):',
        'if any(item.is_dir() or pathlib.PurePosixPath(item.filename).name != item.filename for item in infos):',
        'if any(item.flag_bits & 1 or item.file_size > 1048576 for item in infos):',
        'if sum(item.file_size for item in infos) > 2097152:',
        'if mode and not stat.S_ISREG(mode):',
        '(set -o noclobber; : >"$public_key")',
        'printf \'%s\' "$AUDIT_PUBLIC_KEY_BASE64" | base64 --decode >"$public_key"',
        '[[ "$(sha256sum "$public_key" | awk \'{print $1}\')" == "$AUDIT_PUBLIC_KEY_SHA256" ]]',
        'gh attestation verify "$audit_root/$name" --repo "$AUDIT_REPOSITORY"',
        '--signer-workflow "$AUDIT_REPOSITORY/$AUDIT_WORKFLOW"',
        '--signer-digest "$AUDIT_WORKFLOW_SHA" --source-ref "$AUDIT_REF"',
        '--source-digest "$AUDIT_WORKFLOW_SHA" >/dev/null',
    )
    for marker in audit_markers:
        if marker not in audit_run:
            raise ContractError(
                f"Round 9 independent-audit step is missing fail-closed marker: {marker}"
            )
    if audit_run.count(
        "python3 -B scripts/round9_independent_audit_contract.py verify-remote"
    ) != 2:
        raise ContractError(
            "Round 9 independent-audit step must invoke the remote verifier exactly twice"
        )
    repeated_verifier_arguments = (
        '--evidence "$evidence" --proof "$proof" --asset-dir dist',
        '--public-key "$public_key" --public-key-sha256 "$AUDIT_PUBLIC_KEY_SHA256"',
        '--host-evaluator-public-key-sha256 "$HOST_EVALUATOR_PUBLIC_KEY_SHA256"',
        '--key-id "$AUDIT_KEY_ID" --repository "$GITHUB_REPOSITORY"',
        '--tag v0.16-rc.4 --tag-object-sha "$EXPECTED_TAG_OBJECT"',
        '--commit "$EXPECTED_COMMIT" --tree "$EXPECTED_TREE"',
        '--challenge "$AUDIT_CHALLENGE" --auditor-repository "$AUDIT_REPOSITORY"',
        '--auditor-workflow-name "$AUDIT_WORKFLOW_NAME"',
        '--auditor-workflow "$AUDIT_WORKFLOW" --auditor-ref "$AUDIT_REF"',
        '--auditor-workflow-sha "$AUDIT_WORKFLOW_SHA"',
        '--auditor-run-id "$AUDIT_RUN_ID" --auditor-run-attempt "$AUDIT_RUN_ATTEMPT"',
        '--ledger-ruleset-id "$AUDIT_LEDGER_RULESET_ID"',
        '--ledger-ruleset-name "$AUDIT_LEDGER_RULESET_NAME"',
        '--audit-artifact-id "$AUDIT_ARTIFACT_ID"',
        '--audit-artifact-name "$AUDIT_ARTIFACT_NAME"',
        '--audit-artifact-digest "$AUDIT_ARTIFACT_DIGEST"',
    )
    for argument in repeated_verifier_arguments:
        if audit_run.count(argument) != 2:
            raise ContractError(
                f"Round 9 independent-audit verifier argument is not bound in both paths: {argument}"
            )
    if (
        audit_run.count('for name in round9-independent-audit.json round9-independent-audit-ledger-proof.json; do')
        != 1
        or audit_run.count('gh attestation verify "$audit_root/$name"') != 1
    ):
        raise ContractError(
            "Round 9 independent-audit package must attest exactly the reviewed two files"
        )
    if any(
        forbidden in audit_run
        for forbidden in (
            "continue-on-error",
            "set +e",
            "|| true",
            "printf 'PASS",
            "echo PASS",
        )
    ):
        raise ContractError(
            "Round 9 independent-audit verification contains a fail-open bypass"
        )

    blocked = require_yaml_keys(
        jobs["publication_blocked"],
        ("needs", "if", "runs-on", "timeout-minutes", "permissions", "steps"),
        source,
        "jobs.publication_blocked",
    )
    blocked_needs = yaml_sequence(
        blocked["needs"], source, "jobs.publication_blocked.needs"
    )
    if [
        yaml_scalar(node, source, f"jobs.publication_blocked.needs[{index}]")
        for index, node in enumerate(blocked_needs)
    ] != ["admission", "build"]:
        raise ContractError("Round 9 publication blocker dependency order changed")
    require_yaml_scalar(
        blocked["if"],
        "${{ needs.admission.outputs.publication_permitted == 'true' }}",
        source,
        "jobs.publication_blocked.if",
    )
    require_yaml_scalar(
        blocked["runs-on"], "ubuntu-24.04", source, "jobs.publication_blocked.runs-on"
    )
    require_yaml_scalar(
        blocked["timeout-minutes"],
        "5",
        source,
        "jobs.publication_blocked.timeout-minutes",
        tag="tag:yaml.org,2002:int",
    )
    blocked_permissions = require_yaml_keys(
        blocked["permissions"],
        ("actions", "contents"),
        source,
        "jobs.publication_blocked.permissions",
    )
    require_yaml_scalar(
        blocked_permissions["actions"],
        "read",
        source,
        "jobs.publication_blocked.permissions.actions",
    )
    require_yaml_scalar(
        blocked_permissions["contents"],
        "read",
        source,
        "jobs.publication_blocked.permissions.contents",
    )
    blocked_steps = yaml_sequence(
        blocked["steps"], source, "jobs.publication_blocked.steps"
    )
    if len(blocked_steps) != 1:
        raise ContractError("Round 9 publication blocker must contain exactly one step")
    blocked_step = require_yaml_keys(
        blocked_steps[0],
        ("name", "run"),
        source,
        "jobs.publication_blocked.steps[0]",
    )
    require_yaml_scalar(
        blocked_step["name"],
        "Fail closed after retaining the private candidate artifact",
        source,
        "jobs.publication_blocked.steps[0].name",
    )
    blocked_run = yaml_scalar(
        blocked_step["run"], source, "jobs.publication_blocked.steps[0].run"
    )
    for marker in (
        '[[ "$ROUND9_NEW_PUBLIC_PRERELEASE_CREATION" == \\',
        "BLOCKED_PENDING_EXACT_CANDIDATE_INDEPENDENT_AUDIT_GATE ]]",
        "The private 17-asset candidate remains available as an Actions artifact.",
        "No new public Round 9 prerelease can be created by this workflow.",
        "Required exact-candidate independent-audit evidence is NOT_PROVIDED; the implemented verifier therefore remains fail-closed.",
    ):
        if blocked_run.count(marker) != 1:
            raise ContractError(
                f"Round 9 publication blocker lost exact fail-closed marker: {marker}"
            )
    if blocked_run.count("exit 1") != 1:
        raise ContractError("Round 9 publication blocker must terminate with one exit 1")
    verify_published = require_yaml_keys(
        jobs["verify_published"],
        (
            "needs",
            "if",
            "runs-on",
            "timeout-minutes",
            "permissions",
            "steps",
        ),
        source,
        "jobs.verify_published",
    )
    require_yaml_scalar(
        verify_published["if"],
        "${{ needs.admission.outputs.publication_permitted == 'true' }}",
        source,
        "jobs.verify_published.if",
    )
    checkout_count = 0
    for job_name, job in job_blocks(text).items():
        steps = step_blocks(job)
        checkout_indexes = [
            index
            for index, step in enumerate(steps)
            if re.search(
                r"(?m)^\s+(?:-\s+)?uses:\s*actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$",
                step,
            )
        ]
        checkout_count += len(checkout_indexes)
        for checkout_index in checkout_indexes:
            checkout = steps[checkout_index]
            if (
                not re.search(r"(?m)^\s+persist-credentials:\s*false\s*$", checkout)
                or not re.search(r"(?m)^\s+filter:\s*blob:none\s*$", checkout)
                or not re.search(
                    r"(?m)^\s+sparse-checkout-cone-mode:\s*false\s*$", checkout
                )
                or sparse_patterns_from_checkout(checkout) != ROUND9_SPARSE_PATTERNS
            ):
                raise ContractError(
                    f"Round 9 RC job {job_name} checkout differs from the restricted boundary"
                )
            if checkout_index == 0 or not is_round9_safe_gate_bootstrap_step(
                steps[checkout_index - 1]
            ):
                raise ContractError(
                    f"Round 9 RC job {job_name} must install the exact hash-bound Safe Gate runtime before checkout"
                )
            if checkout_index + 1 >= len(steps) or not is_round9_safe_gate_step(
                steps[checkout_index + 1]
            ):
                raise ContractError(
                    f"Round 9 RC job {job_name} must run Safe Gate immediately after checkout"
                )
    if checkout_count != 2:
        raise ContractError("Round 9 RC workflow must contain exactly two restricted checkouts")
    asset_lists: list[tuple[str, ...]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line.strip().startswith('expected="$(printf \'%s\\n\''):
            continue
        names: list[str] = []
        for asset_line in lines[index + 1 :]:
            stripped = asset_line.strip()
            finished = '| LC_ALL=C sort)"' in stripped
            if finished:
                stripped = stripped.split('| LC_ALL=C sort)"', 1)[0].rstrip()
            if stripped.endswith("\\"):
                stripped = stripped[:-1].rstrip()
            if stripped:
                names.extend(shlex.split(stripped))
            if finished:
                break
        else:
            raise ContractError("Round 9 RC asset allowlist is unterminated")
        asset_lists.append(tuple(names))
    if len(asset_lists) != 3:
        raise ContractError("Round 9 RC workflow must define one 17-asset and two 19-asset allowlists")
    expected_asset_sets = (
        ROUND9_PRIVATE_ASSET_NAMES,
        ROUND9_PUBLISHED_ASSET_NAMES,
        ROUND9_PUBLISHED_ASSET_NAMES,
    )
    for names, expected in zip(asset_lists, expected_asset_sets):
        if len(names) != len(expected) or frozenset(names) != expected:
            raise ContractError("Round 9 RC workflow asset allowlist differs from the exact 17/19 contract")

    embedded_allowlists: list[set[str]] = []
    for match in re.finditer(
        r"(?ms)^\s+expected = \{\n(?P<body>.*?)^\s+\}\n\s+with zipfile\.ZipFile\(source\) as archive:",
        text,
    ):
        try:
            value = ast.literal_eval("{" + match.group("body") + "}")
        except (SyntaxError, ValueError) as exc:
            raise ContractError("Round 9 RC embedded asset allowlist is not a literal set") from exc
        if not isinstance(value, set) or not all(isinstance(item, str) for item in value):
            raise ContractError("Round 9 RC embedded asset allowlist must contain only names")
        embedded_allowlists.append(value)
    if embedded_allowlists.count(set(ROUND9_PRIVATE_ASSET_NAMES)) != 1:
        raise ContractError("Round 9 RC recovered Phase 1 allowlist is not the exact 17 assets")

    for marker in (
        '[[ "$TAG" == v0.16-rc.4 ]]',
        "make unit-test race round6-vet fuzz-smoke round9-fuzz round6-script-test",
        "RC_RELEASE_LANE: round9",
        f"rc_gate.cpa_{CPA_CURRENT_VERSION}_primary_source_compatibility=PASS",
        f'.cpa.primary.version == "{CPA_CURRENT_VERSION}"',
        f'.cpa.primary.commit == "{CPA_CURRENT_COMMIT}"',
        f'.round9.external_evaluation.candidate.cpa_version == "{CPA_CURRENT_VERSION}"',
        ".schema_version == 6",
        ".artifact_count == 17",
        ".artifact_count == 19",
        'round9-development-evidence/v1',
        '.round9.development_evidence.state == "PASS"',
        '.round9.development_evidence.runtime == "go1.26.4"',
        '.round9.development_evidence.platform == "linux/amd64"',
        "python3 -B scripts/round9_machine_reports.py development",
        "python3 -B scripts/round9_machine_reports.py validate-development",
        "python3 -B scripts/round9_independent_audit_contract_test.py",
        "RC_ROUND9_DEVELOPMENT_EVIDENCE_INPUT:",
        '.round9.machine_reports.paired_malicious.schema == "round9-development-paired-malicious-machine-report/v1"',
        ".round9.corpus.paired_malicious.corpus_manifest_version == 2",
        ".round9.corpus.paired_malicious.label_audit.sha256",
        ".round9.audit_contract.decision_kinds == [",
        "round9-external-evaluation/v3",
        "round9-external-counted-mock/v1",
        "round9-public-counted-mock/v1",
        ".round9.external_evaluation.public_counted_mock.total.serialized_executions == 120",
        ".round9.external_evaluation.metrics.public_counted_mock ==",
        ".round9.external_evaluation.development_evidence ==",
        ".round9.counted_mock == .round9.external_evaluation.counted_mock",
        '.payload.development_evidence == $development[0]',
        "actions/runs/${phase1_run_id}/artifacts?per_page=100",
        "actions/artifacts/${phase1_artifact_id}/zip",
        ".id == $run and .run_attempt == $attempt and",
        '.status == "completed" and .conclusion == "success" and',
        "select(.name == $name and .digest == $digest and .expired == false and",
        "expected one Phase 1 artifact",
        "Phase 1 artifact allowlist mismatch",
        "if len(infos) != 17 or set(names) != expected or len(names) != len(set(names)):",
        "gh attestation verify \"$phase1/rc-release-manifest.json\"",
        "independent audit required",
        "ROUND9_NEW_PUBLIC_PRERELEASE_CREATION: BLOCKED_PENDING_EXACT_CANDIDATE_INDEPENDENT_AUDIT_GATE",
        "No new public Round 9 prerelease can be created by this workflow.",
        "Required exact-candidate independent-audit evidence is NOT_PROVIDED; the implemented verifier therefore remains fail-closed.",
    ):
        if marker not in text:
            raise ContractError(f"Round 9 RC workflow is missing reviewed marker: {marker}")
    if text.count("python3 -B scripts/round9_independent_audit_contract_test.py") != 2:
        raise ContractError(
            "Round 9 RC workflow must run independent-audit verifier tests in build and publish"
        )

    current_cpa_marker_counts = {
        f"rc_gate.cpa_{CPA_CURRENT_VERSION}_primary_source_compatibility=PASS": 2,
        f'.cpa.primary.version == "{CPA_CURRENT_VERSION}"': 1,
        f'.cpa.primary.commit == "{CPA_CURRENT_COMMIT}"': 1,
        f'.round9.external_evaluation.candidate.cpa_version == "{CPA_CURRENT_VERSION}"': 1,
    }
    for marker, expected_count in current_cpa_marker_counts.items():
        if text.count(marker) != expected_count:
            raise ContractError(
                f"Round 9 RC workflow must bind the current CPA identity exactly: {marker}"
            )

    public_v13_marker_counts = {
        'round9-public-adversarial-report/v13': 3,
        '.round9.corpus.public_adversarial.payload_records == 24': 3,
        '.round9.corpus.public_adversarial.unique_formal_payloads == 23': 3,
        '.round9.corpus.public_adversarial.unique_historical_payloads == 8': 2,
        '.round9.corpus.public_adversarial.unique_branch_head_payloads == 1': 2,
        '.round9.corpus.public_adversarial.unique_current_prompt_like_payloads == 14': 2,
        '.round9.corpus.public_adversarial.unmerged_candidate_carriers == 1': 2,
        '.round9.corpus.public_adversarial.nondefault_branch_candidate_carriers == 5': 3,
        '.round9.corpus.public_adversarial.release_assets_reviewed == 16': 3,
        '.round9.corpus.public_adversarial.release_assets_with_prompt_entries == 4': 3,
        '.round9.corpus.public_adversarial.release_asset_metadata_records == 199': 3,
        '.round9.corpus.public_adversarial.scenario_payload_executions == 24': 2,
        '.round9.corpus.public_adversarial.serialized_route_executions == 120': 2,
        '.round9.corpus.public_adversarial.direct_active_blocked == 12': 2,
        '.round9.corpus.public_adversarial.direct_active_allowed == 12': 2,
    }
    for marker, expected_count in public_v13_marker_counts.items():
        if text.count(marker) != expected_count:
            raise ContractError(
                f"Round 9 RC workflow must bind the public-v13 marker in every reviewed phase: {marker}"
            )

    external_v3_marker_counts = {
        'round9-external-evaluation/v3': 2,
        'round9-external-counted-mock/v1': 2,
        'round9-public-counted-mock/v1': 2,
        '.round9.external_evaluation.public_counted_mock.total.unique_payloads == 10': 2,
        '.round9.external_evaluation.public_counted_mock.total.serialized_executions == 120': 2,
        '.round9.external_evaluation.public_counted_mock.total.local_blocked == 80': 2,
        '.round9.external_evaluation.public_counted_mock.total.upstream_delta == 40': 2,
        '.round9.external_evaluation.public_counted_mock.total.usage_delta == 40': 2,
        '.round9.external_evaluation.public_counted_mock.total.decision_kind_counts.audit_eligible_malicious_text == 40': 2,
        '.round9.external_evaluation.public_counted_mock.total.decision_kind_counts.block_malicious_text == 80': 2,
        '.round9.external_evaluation.metrics.public_counted_mock ==': 2,
        '.round9.external_evaluation.development_evidence ==': 2,
        '.round9.counted_mock == .round9.external_evaluation.counted_mock': 2,
        'host_ip:"127.0.0.1",host_port:18394,container_port:8317': 4,
        'initial_mode:"audit"': 2,
        'phase_order:["audit","balanced","strict"]': 2,
        'mode_switch_method:"PUT"': 2,
        'mode_switch_endpoint:"/v0/management/plugins/cyber-abuse-guard/config"': 2,
        'status_endpoint:"/v0/management/plugins/cyber-abuse-guard/status"': 2,
        'status_required_after_each_phase_transition:true': 2,
        'mode_switch_authenticated:true': 2,
        'hmac_sha256_challenge_sequential_phase_order_v3': 2,
        '.round9.external_evaluation.metrics.route_order.mode_status_verified ==': 2,
        '.round9.external_evaluation.metrics.route_order.mode_switch_authenticated == true': 2,
        '.round9.external_evaluation.metrics.incomplete.audit ==': 2,
        'round9-external-cpa-runtime-checks/v1': 2,
        '.round9.external_evaluation.metrics.runtime_checks.state == "PASS"': 2,
        '.round9.counted_mock.not_observed == []': 2,
        '.round9.counted_mock.host_results.mode_status_verified ==': 2,
        '.round9.counted_mock.host_results.mode_switch_authenticated == true': 2,
        '.round9.counted_mock.host_results.runtime_checks ==': 2,
    }
    for marker, expected_count in external_v3_marker_counts.items():
        if text.count(marker) != expected_count:
            raise ContractError(
                f"Round 9 RC workflow external-v3/count-Mock binding changed: {marker}"
            )

    threshold_marker_counts = {
        ".round9.corpus.paired_malicious.recall_basis_points == 10000": 2,
        ".round9.corpus.paired_malicious.per_category[];": 2,
        ".round9.external_evaluation.metrics.malicious.recall_basis_points >= 9500": 2,
        ".round9.external_evaluation.metrics.malicious.per_category[];": 2,
    }
    for marker, expected_count in threshold_marker_counts.items():
        if text.count(marker) != expected_count:
            raise ContractError(
                f"Round 9 RC workflow recall threshold layering changed: {marker}"
            )
    if re.search(
        r"\.round9\.corpus\.paired_malicious(?:\.recall_basis_points|\.per_category\[\])"
        r"[^\n]*>=\s*9500",
        text,
    ):
        raise ContractError(
            "Round 9 visible paired-malicious evidence must require exact 100 percent recall"
        )

    for forbidden in (
        ".schema_version == 5",
        "round9-public-adversarial-report/v4",
        "round9-public-adversarial-report/v5",
        'phase_order:["balanced","strict"]',
        "strict_status_endpoint",
        "strict_status_required",
        "strict_status_verified",
        "round9-host-evidence",
    ):
        if forbidden in text:
            raise ContractError(f"Round 9 RC workflow retains a retired active-lane marker: {forbidden}")
    if "contents: write" in text:
        raise ContractError(
            "Round 9 RC workflow must not grant contents write before exact-candidate audit exists"
        )
    if re.search(
        r"(?im)^\s*gh\s+(?:release\s+(?:create|edit|upload|delete)|"
        r"api\b[^\n]*--method\s+(?:POST|PATCH|PUT|DELETE))\b",
        text,
    ):
        raise ContractError(
            "Round 9 RC workflow must not contain a Release mutation path before exact-candidate audit exists"
        )
    for run_text in yaml_run_blocks(text):
        mutation_reason = read_only_gh_api_mutation_reason(run_text)
        if mutation_reason is not None:
            raise ContractError(
                "Round 9 RC workflow GitHub API calls must remain read-only: "
                + mutation_reason
            )
    if re.search(r"(?im)runs-on:\s*(?:windows|macos)", text):
        raise ContractError("Round 9 RC workflow must remain Linux only")
    verify_block = job_blocks(text).get("verify_published", "")
    if not verify_block or re.search(
        r"(?im)(?:contents:\s*write|gh\s+release\s+(?:create|edit|upload|delete)|"
        r"actions/(?:upload-artifact|attest-build-provenance|cache)@|git\s+push\b)",
        verify_block,
    ):
        raise ContractError("Round 9 published-release verifier must remain read-only")


def validate_round8_host_workflow(text: str, source: Path) -> None:
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != ROUND8_HOST_WORKFLOW_SHA256:
        raise ContractError("retired Round 8 Host workflow differs from reviewed fail-only text")
    document = parse_workflow_yaml(text, source)
    root = require_yaml_keys(
        document,
        ("name", "on", "permissions", "concurrency", "jobs"),
        source,
        "workflow",
    )
    require_yaml_scalar(
        root.get("name"),
        "Round 8 protected CPA Host validation",
        source,
        "name",
    )
    on = require_yaml_keys(root.get("on"), ("workflow_dispatch",), source, "on")
    dispatch = require_yaml_keys(
        on.get("workflow_dispatch"), ("inputs",), source, "on.workflow_dispatch"
    )
    inputs = require_yaml_keys(
        dispatch["inputs"], ROUND8_HOST_INPUT_ORDER, source, "on.workflow_dispatch.inputs"
    )
    for input_name, input_node in inputs.items():
        path = f"on.workflow_dispatch.inputs.{input_name}"
        values = require_yaml_keys(
            input_node, ("description", "required", "type"), source, path
        )
        if not yaml_scalar(values["description"], source, f"{path}.description").strip():
            raise ContractError(f"workflow {path}.description may not be empty")
        require_yaml_scalar(
            values["required"],
            "true",
            source,
            f"{path}.required",
            tag="tag:yaml.org,2002:bool",
        )
        require_yaml_scalar(values["type"], "string", source, f"{path}.type")

    permissions = require_yaml_keys(
        root.get("permissions"),
        ("actions", "attestations", "contents", "id-token"),
        source,
        "permissions",
    )
    for permission, expected in (
        ("actions", "read"),
        ("attestations", "write"),
        ("contents", "read"),
        ("id-token", "write"),
    ):
        require_yaml_scalar(
            permissions[permission], expected, source, f"permissions.{permission}"
        )
    concurrency = require_yaml_keys(
        root.get("concurrency"),
        ("group", "cancel-in-progress"),
        source,
        "concurrency",
    )
    require_yaml_scalar(
        concurrency["group"],
        "round8-host-${{ inputs.tag }}",
        source,
        "concurrency.group",
    )
    require_yaml_scalar(
        concurrency["cancel-in-progress"],
        "false",
        source,
        "concurrency.cancel-in-progress",
        tag="tag:yaml.org,2002:bool",
    )
    jobs = require_yaml_keys(
        root.get("jobs"),
        ("base-image-supply-chain", "host-validation"),
        source,
        "jobs",
    )
    base_job = require_yaml_keys(
        jobs["base-image-supply-chain"],
        ("runs-on", "timeout-minutes", "outputs", "steps"),
        source,
        "jobs.base-image-supply-chain",
    )
    require_yaml_scalar(
        base_job.get("runs-on"),
        "ubuntu-24.04",
        source,
        "jobs.base-image-supply-chain.runs-on",
    )
    require_yaml_scalar(
        base_job.get("timeout-minutes"),
        "45",
        source,
        "jobs.base-image-supply-chain.timeout-minutes",
        tag="tag:yaml.org,2002:int",
    )
    base_outputs = require_yaml_keys(
        base_job.get("outputs"),
        ("artifact-id", "artifact-digest"),
        source,
        "jobs.base-image-supply-chain.outputs",
    )
    for name in ("artifact-id", "artifact-digest"):
        require_yaml_scalar(
            base_outputs[name],
            "${{ steps.base_artifact.outputs." + name + " }}",
            source,
            f"jobs.base-image-supply-chain.outputs.{name}",
        )
    base_steps = yaml_sequence(
        base_job.get("steps"), source, "jobs.base-image-supply-chain.steps"
    )
    base_names = (
        "Admit exact immutable RC source for base-image staging",
        "Pull and package exact Docker Official Image manifests",
        "Attest exact immutable base-image bundle",
        "Upload exact immutable base-image bundle",
    )
    base_step_keys = (
        ("name", "env", "shell", "run"),
        ("name", "env", "shell", "run"),
        ("name", "uses", "with"),
        ("name", "id", "uses", "with"),
    )
    if len(base_steps) != len(base_names):
        raise ContractError("Round 8 base-image supply-chain step count changed")
    parsed_base_steps = [
        yaml_mapping(step, source, f"jobs.base-image-supply-chain.steps[{index}]")
        for index, step in enumerate(base_steps)
    ]
    for index, (step, name) in enumerate(zip(parsed_base_steps, base_names)):
        require_yaml_keys(
            base_steps[index],
            base_step_keys[index],
            source,
            f"jobs.base-image-supply-chain.steps[{index}]",
        )
        require_yaml_scalar(
            step.get("name"),
            name,
            source,
            f"jobs.base-image-supply-chain.steps[{index}].name",
        )
        if "if" in step or "continue-on-error" in step:
            raise ContractError("Round 8 base-image supply-chain steps must fail closed")
    for index in (0, 1):
        require_yaml_scalar(
            parsed_base_steps[index].get("shell"),
            "bash",
            source,
            f"jobs.base-image-supply-chain.steps[{index}].shell",
        )
        validate_run_hash(
            parsed_base_steps[index],
            ROUND8_BASE_STEP_RUN_SHA256[index],
            source,
            f"jobs.base-image-supply-chain.steps[{index}]",
        )
    require_yaml_scalar(
        parsed_base_steps[2].get("uses"),
        RC_PROVENANCE_ACTION,
        source,
        "jobs.base-image-supply-chain.steps[2].uses",
    )
    require_yaml_scalar(
        parsed_base_steps[3].get("uses"),
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        source,
        "jobs.base-image-supply-chain.steps[3].uses",
    )
    require_yaml_scalar(
        parsed_base_steps[3].get("id"),
        "base_artifact",
        source,
        "jobs.base-image-supply-chain.steps[3].id",
    )
    base_envs = {
        0: (
            ("TAG", "${{ inputs.tag }}"),
            ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
            ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
            ("ROUND8_LANE_RETIRED", "true"),
        ),
        1: (
            ("GO_REPOSITORY", "docker.io/library/golang"),
            (
                "GO_CANONICAL",
                "docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b",
            ),
            (
                "GO_INDEX_DIGEST",
                "sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b",
            ),
            (
                "GO_PLATFORM_DIGEST",
                "sha256:5a94593d87a066df5abb02969be911524963f53908292aa5a1a6096fc019012a",
            ),
            (
                "GO_IMAGE_ID",
                "sha256:9d9d715d688ced62374388302667e31a6d3a0655c4c9e0ceaf1a4c4886752a62",
            ),
            (
                "GO_LOCAL",
                "cag-round8-base:golang-1.26.4-bookworm-amd64-5a94593d87a0",
            ),
            ("DEBIAN_REPOSITORY", "docker.io/library/debian"),
            (
                "DEBIAN_CANONICAL",
                "docker.io/library/debian:bookworm-20260623@sha256:30482e873082e906a4908c10529180aefb6f77620aea7404b909829fadc5d168",
            ),
            (
                "DEBIAN_INDEX_DIGEST",
                "sha256:30482e873082e906a4908c10529180aefb6f77620aea7404b909829fadc5d168",
            ),
            (
                "DEBIAN_PLATFORM_DIGEST",
                "sha256:129588494497601baa5dbca1df687c835ff166ec4dd3bf307be684f34da07ab5",
            ),
            (
                "DEBIAN_IMAGE_ID",
                "sha256:ee37b64a84a5a803ef11061304de62741b41b1f1b9e2a743b1e7686b12029d79",
            ),
            (
                "DEBIAN_LOCAL",
                "cag-round8-base:debian-bookworm-20260623-amd64-129588494497",
            ),
        ),
    }
    for index, expected_entries in base_envs.items():
        env = require_yaml_keys(
            parsed_base_steps[index].get("env"),
            tuple(name for name, _ in expected_entries),
            source,
            f"jobs.base-image-supply-chain.steps[{index}].env",
        )
        for name, expected_value in expected_entries:
            require_yaml_scalar(
                env[name],
                expected_value,
                source,
                f"jobs.base-image-supply-chain.steps[{index}].env.{name}",
            )
    base_attest_with = require_yaml_keys(
        parsed_base_steps[2].get("with"),
        ("subject-path",),
        source,
        "jobs.base-image-supply-chain.steps[2].with",
    )
    base_attest_paths = tuple(
        yaml_scalar(
            base_attest_with["subject-path"],
            source,
            "jobs.base-image-supply-chain.steps[2].with.subject-path",
        ).splitlines()
    )
    expected_base_paths = (
        "${{ runner.temp }}/round8-base-images/round8-base-images-linux-amd64.tar.gz",
        "${{ runner.temp }}/round8-base-images/round8-base-images-linux-amd64.tar.gz.sha256",
        "${{ runner.temp }}/round8-base-images/round8-base-images.json",
    )
    if base_attest_paths != expected_base_paths:
        raise ContractError("Round 8 base-image attestation subject paths changed")
    base_upload_with = require_yaml_keys(
        parsed_base_steps[3].get("with"),
        (
            "name",
            "path",
            "if-no-files-found",
            "retention-days",
            "compression-level",
        ),
        source,
        "jobs.base-image-supply-chain.steps[3].with",
    )
    require_yaml_scalar(
        base_upload_with["name"],
        "round8-base-images-${{ inputs.expected_commit }}-${{ github.run_id }}-${{ github.run_attempt }}",
        source,
        "jobs.base-image-supply-chain.steps[3].with.name",
    )
    if tuple(
        yaml_scalar(
            base_upload_with["path"],
            source,
            "jobs.base-image-supply-chain.steps[3].with.path",
        ).splitlines()
    ) != expected_base_paths:
        raise ContractError("Round 8 base-image upload paths must match attested subjects")
    require_yaml_scalar(
        base_upload_with["if-no-files-found"],
        "error",
        source,
        "jobs.base-image-supply-chain.steps[3].with.if-no-files-found",
    )
    require_yaml_scalar(
        base_upload_with["retention-days"],
        "30",
        source,
        "jobs.base-image-supply-chain.steps[3].with.retention-days",
        tag="tag:yaml.org,2002:int",
    )
    require_yaml_scalar(
        base_upload_with["compression-level"],
        "0",
        source,
        "jobs.base-image-supply-chain.steps[3].with.compression-level",
        tag="tag:yaml.org,2002:int",
    )
    job = require_yaml_keys(
        jobs["host-validation"],
        ("needs", "environment", "runs-on", "timeout-minutes", "steps"),
        source,
        "jobs.host-validation",
    )
    require_yaml_scalar(
        job.get("needs"),
        "base-image-supply-chain",
        source,
        "jobs.host-validation.needs",
    )
    environment = require_yaml_keys(
        job.get("environment"), ("name",), source, "jobs.host-validation.environment"
    )
    require_yaml_scalar(
        environment["name"],
        "round8-host-validation",
        source,
        "jobs.host-validation.environment.name",
    )
    runs_on = yaml_sequence(job.get("runs-on"), source, "jobs.host-validation.runs-on")
    if tuple(
        yaml_scalar(node, source, f"jobs.host-validation.runs-on[{index}]")
        for index, node in enumerate(runs_on)
    ) != ("self-hosted", "linux", "x64", "cag-round8-sandbox"):
        raise ContractError("Round 8 Host workflow must use only the protected sandbox runner labels")
    require_yaml_scalar(
        job.get("timeout-minutes"),
        "180",
        source,
        "jobs.host-validation.timeout-minutes",
        tag="tag:yaml.org,2002:int",
    )
    steps = yaml_sequence(job.get("steps"), source, "jobs.host-validation.steps")
    expected_names = (
        "Admit exact tag, Phase 1 run, and private artifact",
        "Checkout exact tagged source",
        "Download, byte-bind, and verify the private Phase 1 candidate",
        "Download, attest, and admit immutable base-image bundle",
        "Build bounded private CPA and counted-Mock images after sandbox proof",
        f"Execute the isolated CPA {CPA_ROUND8_VERSION} counted-Mock Host lane",
        "Attest exact Host evidence from this protected workflow",
        "Upload exact attested Host evidence",
        "Record immutable Host admission values",
        "Remove private Host images",
    )
    if len(steps) != len(expected_names):
        raise ContractError("Round 8 Host workflow step count changed")
    parsed_steps = [
        yaml_mapping(step, source, f"jobs.host-validation.steps[{index}]")
        for index, step in enumerate(steps)
    ]
    expected_step_keys = (
        ("name", "id", "env", "shell", "run"),
        ("name", "uses", "with"),
        ("name", "env", "shell", "run"),
        ("name", "env", "shell", "run"),
        ("name", "id", "env", "shell", "run"),
        ("name", "env", "shell", "run"),
        ("name", "uses", "with"),
        ("name", "id", "uses", "with"),
        ("name", "env", "shell", "run"),
        ("name", "if", "env", "shell", "run"),
    )
    for index, (step, expected_name) in enumerate(zip(parsed_steps, expected_names)):
        require_yaml_keys(
            steps[index],
            expected_step_keys[index],
            source,
            f"jobs.host-validation.steps[{index}]",
        )
        require_yaml_scalar(
            step.get("name"), expected_name, source, f"jobs.host-validation.steps[{index}].name"
        )
        if "continue-on-error" in step:
            raise ContractError("Round 8 Host workflow steps must fail closed")
    for index in (0, 2, 3, 4, 5, 8, 9):
        require_yaml_scalar(
            parsed_steps[index].get("shell"),
            "bash",
            source,
            f"jobs.host-validation.steps[{index}].shell",
        )
        validate_run_hash(
            parsed_steps[index],
            ROUND8_HOST_STEP_RUN_SHA256[index],
            source,
            f"jobs.host-validation.steps[{index}]",
        )
    for index, expected_id in ((0, "admission"), (4, "images"), (7, "host_artifact")):
        require_yaml_scalar(
            parsed_steps[index].get("id"),
            expected_id,
            source,
            f"jobs.host-validation.steps[{index}].id",
        )
    for index, expected_action in (
        (1, "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"),
        (6, RC_PROVENANCE_ACTION),
        (7, "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"),
    ):
        require_yaml_scalar(
            parsed_steps[index].get("uses"),
            expected_action,
            source,
            f"jobs.host-validation.steps[{index}].uses",
        )
    expected_envs = {
        0: (
            ("GH_TOKEN", "${{ github.token }}"),
            ("TAG", "${{ inputs.tag }}"),
            ("EXPECTED_TAG_OBJECT", "${{ inputs.expected_tag_object_sha }}"),
            ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
            ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
            ("PHASE1_RUN_ID", "${{ inputs.phase1_run_id }}"),
            ("PHASE1_RUN_ATTEMPT", "${{ inputs.phase1_run_attempt }}"),
            ("PHASE1_ARTIFACT_ID", "${{ inputs.phase1_artifact_id }}"),
            ("PHASE1_ARTIFACT_DIGEST", "${{ inputs.phase1_artifact_digest }}"),
            ("HOST_CHALLENGE", "${{ inputs.challenge }}"),
            ("SANDBOX_ID", "${{ vars.ROUND8_SANDBOX_ID }}"),
            ("DAEMON_ID", "${{ vars.ROUND8_DAEMON_ID }}"),
            ("PROBE_IMAGE_ID", "${{ vars.ROUND8_PROBE_IMAGE_ID }}"),
        ),
        2: (
            ("GH_TOKEN", "${{ github.token }}"),
            ("TAG", "${{ inputs.tag }}"),
            ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
            ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
            ("PHASE1_ARTIFACT_ID", "${{ inputs.phase1_artifact_id }}"),
            ("PHASE1_ARTIFACT_DIGEST", "${{ inputs.phase1_artifact_digest }}"),
        ),
        3: (
            ("GH_TOKEN", "${{ github.token }}"),
            ("TAG", "${{ inputs.tag }}"),
            ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
            (
                "BASE_ARTIFACT_ID",
                "${{ needs.base-image-supply-chain.outputs.artifact-id }}",
            ),
            (
                "BASE_ARTIFACT_DIGEST",
                "${{ needs.base-image-supply-chain.outputs.artifact-digest }}",
            ),
        ),
        4: (
            ("SANDBOX_ID", "${{ vars.ROUND8_SANDBOX_ID }}"),
            ("DAEMON_ID", "${{ vars.ROUND8_DAEMON_ID }}"),
            ("PROBE_IMAGE_ID", "${{ vars.ROUND8_PROBE_IMAGE_ID }}"),
            ("HOST_CHALLENGE", "${{ inputs.challenge }}"),
            ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
            ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
        ),
        5: (
            ("EXPECTED_COMMIT", "${{ inputs.expected_commit }}"),
            ("EXPECTED_TREE", "${{ inputs.expected_tree }}"),
            ("SANDBOX_ID", "${{ vars.ROUND8_SANDBOX_ID }}"),
            ("DAEMON_ID", "${{ vars.ROUND8_DAEMON_ID }}"),
            ("PROBE_IMAGE_ID", "${{ vars.ROUND8_PROBE_IMAGE_ID }}"),
            ("HOST_CHALLENGE", "${{ inputs.challenge }}"),
            ("PHASE1_RUN_ID", "${{ inputs.phase1_run_id }}"),
            ("PHASE1_RUN_ATTEMPT", "${{ inputs.phase1_run_attempt }}"),
            ("PHASE1_ARTIFACT_ID", "${{ inputs.phase1_artifact_id }}"),
            ("PHASE1_ARTIFACT_DIGEST", "${{ inputs.phase1_artifact_digest }}"),
            ("PRIMARY_IMAGE", "${{ steps.images.outputs.primary }}"),
            ("MOCK_IMAGE", "${{ steps.images.outputs.mock }}"),
        ),
        8: (
            ("ARTIFACT_ID", "${{ steps.host_artifact.outputs.artifact-id }}"),
            ("ARTIFACT_DIGEST", "${{ steps.host_artifact.outputs.artifact-digest }}"),
        ),
        9: (
            ("PRIMARY_IMAGE", "${{ steps.images.outputs.primary }}"),
            ("MOCK_IMAGE", "${{ steps.images.outputs.mock }}"),
            (
                "GO_BASE_IMAGE",
                "cag-round8-base:golang-1.26.4-bookworm-amd64-5a94593d87a0",
            ),
            (
                "DEBIAN_BASE_IMAGE",
                "cag-round8-base:debian-bookworm-20260623-amd64-129588494497",
            ),
        ),
    }
    for index, expected_entries in expected_envs.items():
        env = require_yaml_keys(
            parsed_steps[index].get("env"),
            tuple(name for name, _ in expected_entries),
            source,
            f"jobs.host-validation.steps[{index}].env",
        )
        for name, expected_value in expected_entries:
            require_yaml_scalar(
                env[name],
                expected_value,
                source,
                f"jobs.host-validation.steps[{index}].env.{name}",
            )

    checkout_with = require_yaml_keys(
        parsed_steps[1].get("with"),
        ("ref", "fetch-depth", "persist-credentials"),
        source,
        "jobs.host-validation.steps[1].with",
    )
    require_yaml_scalar(
        checkout_with["ref"],
        "${{ inputs.tag }}",
        source,
        "jobs.host-validation.steps[1].with.ref",
    )
    require_yaml_scalar(
        checkout_with["fetch-depth"],
        "0",
        source,
        "jobs.host-validation.steps[1].with.fetch-depth",
        tag="tag:yaml.org,2002:int",
    )
    require_yaml_scalar(
        checkout_with["persist-credentials"],
        "false",
        source,
        "jobs.host-validation.steps[1].with.persist-credentials",
        tag="tag:yaml.org,2002:bool",
    )
    attest_with = require_yaml_keys(
        parsed_steps[6].get("with"),
        ("subject-path",),
        source,
        "jobs.host-validation.steps[6].with",
    )
    attest_paths = tuple(
        yaml_scalar(
            attest_with["subject-path"],
            source,
            "jobs.host-validation.steps[6].with.subject-path",
        ).splitlines()
    )
    if attest_paths != (
        "${{ runner.temp }}/round8-host-output/round8-host-evidence.json",
        "${{ runner.temp }}/round8-host-output/round8-host-evidence.json.sha256",
    ):
        raise ContractError("Round 8 Host attestation subject paths changed")
    upload_with = require_yaml_keys(
        parsed_steps[7].get("with"),
        ("name", "path", "if-no-files-found", "retention-days"),
        source,
        "jobs.host-validation.steps[7].with",
    )
    require_yaml_scalar(
        upload_with["name"],
        "round8-host-evidence-${{ inputs.expected_commit }}-${{ github.run_id }}-${{ github.run_attempt }}",
        source,
        "jobs.host-validation.steps[7].with.name",
    )
    upload_paths = tuple(
        yaml_scalar(
            upload_with["path"],
            source,
            "jobs.host-validation.steps[7].with.path",
        ).splitlines()
    )
    if upload_paths != attest_paths:
        raise ContractError("Round 8 Host upload paths must exactly match attested subjects")
    require_yaml_scalar(
        upload_with["if-no-files-found"],
        "error",
        source,
        "jobs.host-validation.steps[7].with.if-no-files-found",
    )
    require_yaml_scalar(
        upload_with["retention-days"],
        "30",
        source,
        "jobs.host-validation.steps[7].with.retention-days",
        tag="tag:yaml.org,2002:int",
    )
    require_yaml_scalar(
        parsed_steps[9].get("if"),
        "${{ always() }}",
        source,
        "jobs.host-validation.steps[9].if",
    )
    for index in range(9):
        if "if" in parsed_steps[index]:
            raise ContractError("Round 8 Host admission/execution steps may not be conditional")

    required_markers = (
        "${{ vars.ROUND8_SANDBOX_ID }}",
        "${{ vars.ROUND8_DAEMON_ID }}",
        "${{ vars.ROUND8_PROBE_IMAGE_ID }}",
        "base-image-supply-chain",
        "docker buildx imagetools inspect --raw",
        "docker pull --quiet --platform linux/amd64",
        "round8-base-images-linux-amd64.tar.gz",
        "github-attested-digest-bundle/v1",
        "docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b",
        "sha256:5a94593d87a066df5abb02969be911524963f53908292aa5a1a6096fc019012a",
        "sha256:9d9d715d688ced62374388302667e31a6d3a0655c4c9e0ceaf1a4c4886752a62",
        "docker.io/library/debian:bookworm-20260623@sha256:30482e873082e906a4908c10529180aefb6f77620aea7404b909829fadc5d168",
        "sha256:129588494497601baa5dbca1df687c835ff166ec4dd3bf307be684f34da07ab5",
        "sha256:ee37b64a84a5a803ef11061304de62741b41b1f1b9e2a743b1e7686b12029d79",
        "${{ needs.base-image-supply-chain.outputs.artifact-id }}",
        "${{ needs.base-image-supply-chain.outputs.artifact-digest }}",
        "validate-base-bundle",
        '--base-images-archive "$RUNNER_TEMP/round8-base-images/round8-base-images-linux-amd64.tar.gz"',
        '--base-images-manifest "$RUNNER_TEMP/round8-base-images/round8-base-images.json"',
        '[[ "${RUNNER_ENVIRONMENT}" == self-hosted ]]',
        '.path == ".github/workflows/release-rc.yml"',
        '.run_attempt == $run_attempt',
        '.digest == $digest and .expired == false',
        '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release-rc.yml"',
        '--signer-digest "$EXPECTED_COMMIT"',
        '--source-ref "refs/tags/$TAG"',
        '--source-digest "$EXPECTED_COMMIT"',
        "gh api --header 'Accept: application/octet-stream'",
        "--workflow-run-id \"$GITHUB_RUN_ID\"",
        "--phase1-artifact-digest \"$PHASE1_ARTIFACT_DIGEST\"",
        '(.cpa | keys) == ["primary"]',
        f'.cpa.primary.version == "{CPA_ROUND8_VERSION}"',
        f'.cpa.primary.commit == "{CPA_ROUND8_COMMIT}"',
        'subject-path: |',
        "round8-host-evidence-${{ inputs.expected_commit }}-${{ github.run_id }}-${{ github.run_attempt }}",
        "artifact-digest",
        "docker image rm --force",
    )
    for marker in required_markers:
        if marker not in text:
            raise ContractError(f"Round 8 Host workflow is missing reviewed marker: {marker}")
    build_run = yaml_scalar(
        parsed_steps[4].get("run"), source, "jobs.host-validation.steps[4].run"
    )
    execute_run = yaml_scalar(
        parsed_steps[5].get("run"), source, "jobs.host-validation.steps[5].run"
    )
    for marker in (
        '--sandbox-id "$SANDBOX_ID"',
        '--daemon-id "$DAEMON_ID"',
        '--probe-image-id "$PROBE_IMAGE_ID"',
        '--challenge "$HOST_CHALLENGE"',
    ):
        if build_run.count(marker) != 1 or execute_run.count(marker) != 1:
            raise ContractError(
                "Round 8 Host workflow must bind each sandbox parameter exactly once "
                f"in both execution steps: {marker}"
            )
    if execute_run.count('.execution.sandbox.locality_challenge == "PASS"') != 1:
        raise ContractError("Round 8 Host workflow must require exactly one locality PASS assertion")
    forbidden = (
        "host_evidence_base64",
        "operator-supplied unsigned",
        "contents: write",
        "runs-on: windows",
        "runs-on: macos",
        "public.ecr.aws",
        "DOCKER_HOST: tcp://",
        "DOCKER_HOST: ssh://",
        "COMPATIBILITY_IMAGE",
        "--compatibility-image",
        "v7.2.88",
        CPA_CURRENT_VERSION,
        CPA_CURRENT_COMMIT,
    )
    for marker in forbidden:
        if marker.lower() in text.lower():
            raise ContractError(f"Round 8 Host workflow contains forbidden marker: {marker}")


def validate_archived_rc_workflow(text: str, source: Path) -> None:
    parse_workflow_yaml(text, source)
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != RC_RELEASE_WORKFLOW_SHA256:
        raise ContractError("archived RC workflow differs from the exact reviewed contract")
    required = (
        "RC release v0.15-rc.2 - Linux sandbox validation",
        "Bind RC authorization to annotated exact-main tag before checkout",
        "Bind RC admission to successful exact-main push CI",
        "Checkout exact RC tag with restricted data excluded",
        "Recheck restricted-data and workflow contracts",
        "Recheck regressions and latest CPA v7.2.86 contracts",
        "Run RC-versioned CPA Host integration",
        "Build and reproduce exact RC release assets",
        "Reverify transferred RC assets without repository source",
        "Recheck immutable tag and main before publication",
        "Create, byte-check, and publish v0.15-rc.2 prerelease",
        "SANDBOX_ONLY / SERVER_VALIDATION_REQUIRED / NOT_FORMAL / NOT_ROUND6_CANDIDATE",
        "cyber-abuse-guard_0.15-rc.2_linux_amd64.zip",
        "rc-release-manifest.json.sha256",
        "--draft",
        "--prerelease",
        "--latest=false",
    )
    for marker in required:
        if marker not in text:
            raise ContractError(f"archived RC workflow is missing reviewed marker: {marker}")
    if text.count("contents: write") != 1:
        raise ContractError("archived RC workflow must preserve contents: write only in publish")
    if re.search(r"(?im)runs-on:\s*(?:windows|macos)", text):
        raise ContractError("archived RC workflow must remain Linux only")
    if "round6-prerelease-attestation.json" in text or "formal-release-attestation.json" in text:
        raise ContractError("archived RC workflow may not emit formal evidence assets")


def validate_round6_reproducibility_script(text: str, source: Path) -> None:
    match = re.search(
        r"sparse-checkout\s+set\s+--no-cone(?P<body>.*?)\n\s*git\s+-C\s+[^\n]+\s+checkout",
        text,
        re.DOTALL,
    )
    if not match:
        raise ContractError(f"Round6 reproducibility script lacks a static sparse checkout: {source}")
    patterns = tuple(
        re.findall(r"['\"]((?:/\*|!/[^'\"]+))['\"]", match.group("body"))
    )
    if patterns != ROUND6_SPARSE_PATTERNS:
        raise ContractError(
            f"Round6 reproducibility sparse checkout differs from the workflow contract: {source}"
        )
    if text.count(ROUND6_REPRODUCIBILITY_ENTRY_MODE_CONTRACT) != 1:
        raise ContractError(
            "Round6 reproducibility entry mode must keep development separate from release: "
            f"{source}"
        )
    if text.count(ROUND6_REPRODUCIBILITY_MODE_CONTRACT) != 1:
        raise ContractError(
            "Round6 reproducibility modes must keep the exact candidate and formal assertions: "
            f"{source}"
        )
    if text.count(ROUND6_REPRODUCIBILITY_PACKAGE_BRANCH_CONTRACT) != 1:
        raise ContractError(
            "Round6 reproducibility package-release must remain in the exact formal-only branch: "
            f"{source}"
        )
    for contract in ROUND6_REPRODUCIBILITY_CHECKSUMS_CONTRACT:
        if text.count(contract) != 1:
            raise ContractError(
                "Round6 reproducibility must generate and compare the exact checksums manifest: "
                f"{source}"
            )
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != ROUND6_REPRODUCIBILITY_SCRIPT_SHA256
    ):
        raise ContractError(
            f"Round6 reproducibility script must match the exact reviewed safety contract: {source}"
        )


def validate_round6_linux_build_script(text: str, source: Path) -> None:
    commands = tuple(
        command
        for command in logical_shell_commands(text)
        if not command.lstrip().startswith("#")
    )
    required_prefix = (
        "set -euo pipefail",
        'root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"',
        'source "$root/scripts/release-common.sh"',
        'go_bin="${GO:-go}"',
        'release_require_commands "$go_bin" file sha256sum git sed awk sort tail readelf mkdir rm basename',
        "release_init",
        "release_assert_tag",
        'dist="${DIST_DIR:-$root/dist}"',
        'artifact="$dist/cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"',
        'if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then',
        'echo "build-linux-amd64.sh requires an amd64 Linux environment (native, WSL2, or Docker)." >&2',
        "exit 1",
        "fi",
        'go_version="$($go_bin env GOVERSION)"',
        'if [[ "$go_version" != go1.26.4 ]]; then',
        "printf 'build-linux-amd64.sh requires Go go1.26.4, got %s\\n' \"$go_version\" >&2",
        "exit 1",
        "fi",
        'mkdir -p "$dist"',
        'cd "$root"',
        'ldflags="-s -w -buildid="',
        'ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard-next/internal/buildinfo.Version=$RELEASE_ARTIFACT_VERSION"',
        'ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard-next/internal/buildinfo.Commit=$RELEASE_GIT_COMMIT"',
        'ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard-next/internal/buildinfo.RulesetVersion=$RELEASE_RULESET_VERSION"',
        'ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard-next/internal/buildinfo.RulesetSHA256=$RELEASE_RULESET_SHA256"',
        'ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard-next/internal/buildinfo.Dirty=$RELEASE_DIRTY"',
        'export SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH"',
        'CGO_ENABLED=1 GOOS=linux GOARCH=amd64 "$go_bin" build -mod=readonly -trimpath -buildvcs=false -buildmode=c-shared -tags=sqlite_omit_load_extension -ldflags="$ldflags" -o "$artifact" ./cmd/cyber-abuse-guard',
        'rm -f "${artifact%.so}.h"',
        '(cd "$dist" && sha256sum "$(basename "$artifact")" > "$(basename "$artifact").sha256")',
        'OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-ruleset-manifest.sh"',
    )
    required_sequence = (
        'OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-build-metadata.sh"',
        'file "$artifact"',
        'glibc_tags="$(readelf --version-info --wide "$artifact" | awk \'{ line = $0; while (match(line, /GLIBC_[A-Za-z0-9_.]+/)) { print substr(line, RSTART, RLENGTH); line = substr(line, RSTART + RLENGTH) } }\' | LC_ALL=C sort -u)"',
        'if [[ -z "$glibc_tags" ]]; then',
        "echo 'build artifact has no auditable GLIBC version-needed tags' >&2",
        "exit 1",
        "fi",
        'while IFS= read -r glibc_tag; do',
        'if [[ ! "$glibc_tag" =~ ^GLIBC_[0-9]+([.][0-9]+)*$ ]]; then',
        "printf 'build requires unsupported non-numeric glibc version tag %s\\n' \"$glibc_tag\" >&2",
        "exit 1",
        "fi",
        'done <<<"$glibc_tags"',
        'max_glibc="$(printf \'%s\\n\' "$glibc_tags" | sed \'s/^GLIBC_//\' | LC_ALL=C sort -Vu | tail -1)"',
        'if [[ -z "$max_glibc" || "$(printf \'%s\\n\' "$max_glibc" \'2.34\' | sort -V | tail -1)" != 2.34 ]]; then',
        "printf 'build requires unsupported glibc %s; maximum allowed is 2.34\\n' \"$max_glibc\" >&2",
        "exit 1",
        "fi",
        '(cd "$dist" && sha256sum -c "$(basename "$artifact").sha256")',
        "release_assert_source_unchanged",
    )
    required_suffix = (
        "printf 'build identity: version=%s commit=%s tree=%s ruleset=%s ruleset_sha256=%s classifier=%s classifier_sha256=%s scanner=%s dirty=%s\\n' \"$RELEASE_ARTIFACT_VERSION\" \"$RELEASE_GIT_COMMIT\" \"$RELEASE_GIT_TREE\" \"$RELEASE_RULESET_VERSION\" \"$RELEASE_RULESET_SHA256\" \"$RELEASE_CLASSIFIER_POLICY_VERSION\" \"$RELEASE_CLASSIFIER_POLICY_SHA256\" \"$RELEASE_STREAMING_SCANNER\" \"$RELEASE_DIRTY\"",
    )
    if commands != required_prefix + required_sequence + required_suffix:
        raise ContractError(
            f"Round6 Linux build must execute the exact glibc 2.34 reviewed fail-closed command sequence: {source}"
        )


def parse_makefile(
    text: str,
) -> tuple[dict[str, set[str]], dict[str, str], dict[str, set[str]]]:
    dependencies: dict[str, set[str]] = defaultdict(set)
    dynamic_dependencies: dict[str, set[str]] = defaultdict(set)
    recipes: dict[str, list[str]] = defaultdict(list)
    current_targets: list[str] = []
    for line in logical_make_lines(text):
        if line.startswith("\t"):
            for target in current_targets:
                recipes[target].append(line[1:])
            continue
        current_targets = []
        match = re.match(
            r"^([A-Za-z0-9_.%/-]+(?:\s+[A-Za-z0-9_.%/-]+)*):\s*(.*)$", line
        )
        if not match:
            continue
        targets = match.group(1).split()
        raw_dependencies = match.group(2).split("#", 1)[0].strip()
        for target in targets:
            dependencies.setdefault(target, set())
        for candidate in raw_dependencies.split():
            if candidate == "|":
                continue
            if "$" in candidate or "`" in candidate:
                for target in targets:
                    dynamic_dependencies[target].add(candidate)
                continue
            if TARGET_NAME.match(candidate):
                for target in targets:
                    dependencies[target].add(candidate)
        current_targets = targets
    return (
        dict(dependencies),
        {target: "\n".join(lines) for target, lines in recipes.items()},
        dict(dynamic_dependencies),
    )


def validate_round6_go_safe_development_script(text: str, source: Path) -> None:
    if "integration/round8countedmock" in text or "round8_counted_mock_module" in text:
        raise ContractError(
            f"active safe-development test modes must not execute Round 8 counted-Mock: {source}"
        )
    required_round9_commands = (
        'round9_counted_mock_module="integration/round9countedmock"',
        '"$go_bin" -C "$round9_counted_mock_module" list . >/dev/null',
        '"$go_bin" -C "$round9_counted_mock_module" test -count=1 .',
        'CGO_ENABLED=1 "$go_bin" -C "$round9_counted_mock_module" test -race -count=1 .',
    )
    if any(text.count(command) != 1 for command in required_round9_commands):
        raise ContractError(
            f"safe-development test modes lost the exact Round 9 counted-Mock contract: {source}"
        )


def validate_round6_makefile_contract(text: str, source: Path) -> None:
    dependencies, recipes, _ = parse_makefile(text)
    actionlint_assignments = re.findall(
        r"(?m)^ACTIONLINT_VERSION\s*([?:+]?=)\s*(\S+)\s*$", text
    )
    if actionlint_assignments != [("?=", ACTIONLINT_VERSION)]:
        raise ContractError(
            f"Makefile must pin actionlint exactly at {ACTIONLINT_VERSION}: {source}"
        )
    if "workflow-lint" not in dependencies.get(".PHONY", set()):
        raise ContractError(f"workflow-lint must remain a phony Make target: {source}")
    if dependencies.get("workflow-lint") != set():
        raise ContractError(f"workflow-lint may not gain Make dependencies: {source}")
    actionlint_commands = tuple(
        " ".join(line.split())
        for line in recipes.get("workflow-lint", "").splitlines()
        if line.strip()
    )
    if actionlint_commands != (ACTIONLINT_COMMAND,):
        raise ContractError(
            "workflow-lint must use the pinned actionlint version, reviewed config, "
            f"and all {len(ACTIVE_WORKFLOW_PATHS)} active workflows in exact order: {source}"
        )
    active_module_commands = tuple(
        " ".join(line.split())
        for line in recipes.get("module-verify", "").splitlines()
        if line.strip()
    )
    expected_active_module_commands = (
        "$(GO) mod verify",
        "$(GO) mod tidy -diff",
        "$(GO) -C integration/round9countedmock mod verify",
        "$(GO) -C integration/round9countedmock mod tidy -diff",
        "$(GO) -C integration/pluginstorecontract mod verify",
        "$(GO) -C integration/pluginstorecontract mod tidy -diff",
        "$(GO) -C integration/cpalatestcontract mod verify",
        "$(GO) -C integration/cpalatestcontract mod tidy -diff",
    )
    if active_module_commands != expected_active_module_commands:
        raise ContractError(
            f"module-verify must exclude historical Round 8 counted-Mock: {source}"
        )

    module_commands = tuple(
        " ".join(line.split())
        for line in recipes.get("round6-module-verify", "").splitlines()
        if line.strip()
    )
    expected_module_commands = (
        "$(GO) mod verify",
        "$(GO) list -tags=$(TEST_TAGS) -deps $(ROUND6_SAFE_PACKAGES) >/dev/null",
        "$(GO) -C integration/round9countedmock mod verify",
        "$(GO) -C integration/round9countedmock mod tidy -diff",
        "$(GO) -C integration/pluginstorecontract mod verify",
        "$(GO) -C integration/pluginstorecontract mod tidy -diff",
        "$(GO) -C integration/cpalatestcontract mod verify",
        "$(GO) -C integration/cpalatestcontract mod tidy -diff",
    )
    if module_commands != expected_module_commands:
        raise ContractError(
            "round6-module-verify must tidy-diff only the three current integration modules: "
            f"{source}"
        )

    round6_vet_commands = tuple(
        " ".join(line.split())
        for line in recipes.get("round6-vet", "").splitlines()
        if line.strip()
    )
    if round6_vet_commands != (
        "$(GO) vet -tags=$(TEST_TAGS) $(ROUND6_SAFE_PACKAGES)",
        "$(GO) -C integration/round9countedmock vet .",
    ):
        raise ContractError(f"round6-vet must exclude historical Round 8 counted-Mock: {source}")

    historical_target = "round8-counted-mock-historical-regression"
    if historical_target not in dependencies.get(".PHONY", set()):
        raise ContractError(f"historical Round 8 counted-Mock target must be phony: {source}")
    if dependencies.get(historical_target) != set():
        raise ContractError(
            f"historical Round 8 counted-Mock target may not gain dependencies: {source}"
        )
    historical_commands = tuple(
        " ".join(line.split())
        for line in recipes.get(historical_target, "").splitlines()
        if line.strip()
    )
    if historical_commands != (
        "$(GO) -C integration/round8countedmock mod verify",
        "$(GO) -C integration/round8countedmock mod tidy -diff",
        "$(GO) -C integration/round8countedmock vet .",
        "$(GO) -C integration/round8countedmock test -count=1 .",
    ):
        raise ContractError(
            f"historical Round 8 counted-Mock target differs from its isolated contract: {source}"
        )
    fuzz_smoke_commands = tuple(
        " ".join(line.split())
        for line in recipes.get("fuzz-smoke", "").splitlines()
        if line.strip()
    )
    expected_fuzz_smoke_commands = (
        "@listed=\"$$($(GO) test ./internal/extract -list='^(FuzzExtractText|FuzzExtractRequestMediaMemberOrder|FuzzExtractRequestScalarMediaCarrierPermutation|FuzzExtractRequestContentType|FuzzExtractRequestMultipart|FuzzExtractRequestMultipartUnknownFieldEvidenceOrder|FuzzRound6JSONStringChunkDecoderMatchesStdlib)$$')\" || exit $$?; for fuzz_name in FuzzExtractText FuzzExtractRequestMediaMemberOrder FuzzExtractRequestScalarMediaCarrierPermutation FuzzExtractRequestContentType FuzzExtractRequestMultipart FuzzExtractRequestMultipartUnknownFieldEvidenceOrder FuzzRound6JSONStringChunkDecoderMatchesStdlib; do printf '%s\\n' \"$$listed\" | grep -Fxq \"$$fuzz_name\" || { echo \"required extract fuzz seed target $$fuzz_name is missing\" >&2; exit 1; }; done",
        "$(GO) test ./internal/extract -run='^(FuzzExtractText|FuzzExtractRequestMediaMemberOrder|FuzzExtractRequestScalarMediaCarrierPermutation|FuzzExtractRequestContentType|FuzzExtractRequestMultipart|FuzzExtractRequestMultipartUnknownFieldEvidenceOrder|FuzzRound6JSONStringChunkDecoderMatchesStdlib)$$' -count=1",
        "@listed=\"$$($(GO) test ./internal/classifier -list='^(FuzzClassifier|FuzzRound6StreamingChunkAndRoleBoundaries|FuzzMetaOverrideClausePermutation|FuzzMetaOverrideEncodingAndPartSplit|FuzzDefensiveQuotedSampleBoundary)$$')\" || exit $$?; for fuzz_name in FuzzClassifier FuzzRound6StreamingChunkAndRoleBoundaries FuzzMetaOverrideClausePermutation FuzzMetaOverrideEncodingAndPartSplit FuzzDefensiveQuotedSampleBoundary; do printf '%s\\n' \"$$listed\" | grep -Fxq \"$$fuzz_name\" || { echo \"required classifier fuzz seed target $$fuzz_name is missing\" >&2; exit 1; }; done",
        "$(GO) test ./internal/classifier -run='^(FuzzClassifier|FuzzRound6StreamingChunkAndRoleBoundaries|FuzzMetaOverrideClausePermutation|FuzzMetaOverrideEncodingAndPartSplit|FuzzDefensiveQuotedSampleBoundary)$$' -count=1",
        "@$(GO) test ./internal/config -list='^FuzzConfigParser$$' | grep -Fxq 'FuzzConfigParser' || { echo 'required config fuzz seed target FuzzConfigParser is missing' >&2; exit 1; }",
        "$(GO) test ./internal/config -run='^FuzzConfigParser$$' -count=1",
    )
    if fuzz_smoke_commands != expected_fuzz_smoke_commands:
        raise ContractError(
            f"fuzz-smoke must fail closed over the exact deterministic seed target set: {source}"
        )
    round9_fuzz_commands = tuple(
        " ".join(line.split())
        for line in recipes.get("round9-fuzz", "").splitlines()
        if line.strip()
    )
    expected_round9_fuzz_commands = (
        "@set -euo pipefail; [[ \"$$(uname -s)\" == Linux ]] || { echo 'round9-fuzz requires a Linux host' >&2; exit 1; }; case \"$$(uname -m)\" in x86_64|amd64) ;; *) echo 'round9-fuzz requires linux/amd64' >&2; exit 1 ;; esac; [[ \"$$($(GO) env GOOS)\" == linux && \"$$($(GO) env GOARCH)\" == amd64 ]] || { echo 'round9-fuzz requires GOOS=linux GOARCH=amd64' >&2; exit 1; }; [[ \"$$($(GO) version | awk '{print $$3}')\" == go1.26.4 ]] || { echo 'round9-fuzz requires Go 1.26.4' >&2; exit 1; }; case \"$(ROUND9_FUZZTIME)\" in 1s|2s|3s|4s|5s|6s|7s|8s|9s|10s) ;; *) echo 'ROUND9_FUZZTIME must be an integer duration from 1s through 10s' >&2; exit 1 ;; esac",
        "GOMAXPROCS=2 $(GO) test -tags=$(TEST_TAGS) ./internal/classifier -run='^$$' -fuzz='^FuzzClassifier$$' -fuzztime='$(ROUND9_FUZZTIME)' -parallel=1",
        "GOMAXPROCS=2 $(GO) test -tags=$(TEST_TAGS) ./internal/extract -run='^$$' -fuzz='^FuzzExtractRequestContentType$$' -fuzztime='$(ROUND9_FUZZTIME)' -parallel=1",
        "GOMAXPROCS=2 $(GO) test -tags=$(TEST_TAGS) ./internal/audit -run='^$$' -fuzz='^FuzzRound9AuditDecisionExplanationV2$$' -fuzztime='$(ROUND9_FUZZTIME)' -parallel=1",
    )
    if text.count("ROUND9_FUZZTIME ?= 5s") != 1 or round9_fuzz_commands != expected_round9_fuzz_commands:
        raise ContractError(
            f"round9-fuzz must retain the exact Linux/amd64 Go 1.26.4 bounded real-fuzz contract: {source}"
        )
    benchmark_commands = tuple(
        " ".join(line.split())
        for line in recipes.get("benchmark", "").splitlines()
        if line.strip()
    )
    expected_benchmark_commands = (
        "$(GO) test ./internal/classifier -run='^(TestCandidateRichMaxPartsAllocationBound|TestCandidateRichProfiledMaxPartsPerformanceBound|TestClassifier(Adversarial)?PerformanceAcceptance|TestClassifierDirectiveAllocationAcceptance|TestDirectiveClauseOverflowPerformanceBoundary|TestRound5MetaOverridePerformanceAcceptance|TestRound5AdjacentNegationCandidateFloodPerformanceAcceptance)$$' -count=1 -v",
        "$(GO) test ./internal/classifier -run='^$$' -bench=. -benchmem -count=3",
        "@$(GO) test ./internal/extract -list='^BenchmarkRound9ToolAssociationPlanning$$' | grep -Fxq 'BenchmarkRound9ToolAssociationPlanning' || { echo 'required Round9 tool-association planning benchmark is missing' >&2; exit 1; }",
        "$(GO) test ./internal/extract -run='^$$' -bench='^(BenchmarkExtractRequest(ReverseOrderedMedia|Multipart|ScalarCarrierPermutation).*|BenchmarkMultipartUnknownFileField(1MiB|8MiB)|BenchmarkRound9ToolAssociationPlanning)$$' -benchmem -benchtime=3x",
    )
    if benchmark_commands != expected_benchmark_commands:
        raise ContractError(
            f"benchmark must retain the reviewed classifier hard bounds and measurement set: {source}"
        )
    if dependencies.get("round6-benchmark") != {"benchmark"}:
        raise ContractError(
            f"round6-benchmark must retain the reviewed benchmark dependency: {source}"
        )
    commands = tuple(
        " ".join(line.split())
        for line in recipes.get("round6-benchmark", "").splitlines()
        if line.strip()
    )
    expected = (
        "@$(GO) test ./internal/extract -list='^TestRound6LongTextScaleAcceptance$$' | grep -Fxq 'TestRound6LongTextScaleAcceptance' || { echo 'required Round6 long-text scale acceptance test is missing' >&2; exit 1; }",
        "$(GO) test ./internal/extract -count=1 -v -run='^TestRound6LongTextScaleAcceptance$$'",
        "@$(GO) test ./internal/extract -list='^BenchmarkRound6ScanLongJSON$$' | grep -Fxq 'BenchmarkRound6ScanLongJSON' || { echo 'required Round6 long-JSON benchmark is missing' >&2; exit 1; }",
        "$(GO) test ./internal/extract -run='^$$' -bench='^BenchmarkRound6ScanLongJSON$$' -benchmem -benchtime=1x -count=1",
        "@$(GO) test ./internal/audit -list='^TestRawCapturePerformanceAcceptance$$' | grep -Fxq 'TestRawCapturePerformanceAcceptance' || { echo 'required raw-capture performance acceptance test is missing' >&2; exit 1; }",
        "CAG_RAW_CAPTURE_PERFORMANCE_ACCEPTANCE=1 $(GO) test ./internal/audit -count=1 -v -run='^TestRawCapturePerformanceAcceptance$$'",
        "@listed=\"$$($(GO) test ./internal/audit -list='^(BenchmarkPrepareRawCapture|BenchmarkRecordRawCaptureQueue|BenchmarkEnqueueEventWithRawCapture)$$')\" || exit $$?; for benchmark_name in BenchmarkPrepareRawCapture BenchmarkRecordRawCaptureQueue BenchmarkEnqueueEventWithRawCapture; do printf '%s\\n' \"$$listed\" | grep -Fxq \"$$benchmark_name\" || { echo \"required raw-capture benchmark $$benchmark_name is missing\" >&2; exit 1; }; done",
        "$(GO) test ./internal/audit -run='^$$' -bench='^(BenchmarkPrepareRawCapture|BenchmarkRecordRawCaptureQueue|BenchmarkEnqueueEventWithRawCapture)$$' -benchmem -benchtime=1x -count=1",
        "@$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -list='^TestRawCaptureManagementResponsePerformanceAcceptance$$' | grep -Fxq 'TestRawCaptureManagementResponsePerformanceAcceptance' || { echo 'required raw-capture management performance acceptance test is missing' >&2; exit 1; }",
        "$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -count=1 -v -run='^TestRawCaptureManagementResponsePerformanceAcceptance$$'",
        "@$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -list='^BenchmarkRawCaptureManagementResponseBudget$$' | grep -Fxq 'BenchmarkRawCaptureManagementResponseBudget' || { echo 'required raw-capture management response benchmark is missing' >&2; exit 1; }",
        "$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -run='^$$' -bench='^BenchmarkRawCaptureManagementResponseBudget$$' -benchmem -benchtime=1x -count=1",
        "@$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -list='^TestFourRepositoryFullRoutePerformanceAcceptance$$' | grep -Fxq 'TestFourRepositoryFullRoutePerformanceAcceptance' || { echo 'required Round6 full-route performance acceptance test is missing' >&2; exit 1; }",
        "$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -count=1 -v -run='^TestFourRepositoryFullRoutePerformanceAcceptance$$'",
        "@listed=\"$$($(GO) test -tags=$(TEST_TAGS) ./internal/plugin -list='^(BenchmarkFourRepositoryModelRoute|BenchmarkFourRepositoryParallelCleanSubjectEnabled|BenchmarkBalancedAuditOnWrapperOnly17166ModelRoute)$$')\" || exit $$?; for benchmark_name in BenchmarkFourRepositoryModelRoute BenchmarkFourRepositoryParallelCleanSubjectEnabled BenchmarkBalancedAuditOnWrapperOnly17166ModelRoute; do printf '%s\\n' \"$$listed\" | grep -Fxq \"$$benchmark_name\" || { echo \"required Round6 full-route benchmark $$benchmark_name is missing\" >&2; exit 1; }; done",
        "$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -run='^$$' -bench='^(BenchmarkFourRepositoryModelRoute|BenchmarkFourRepositoryParallelCleanSubjectEnabled|BenchmarkBalancedAuditOnWrapperOnly17166ModelRoute)$$' -benchmem -benchtime=3x -count=1",
    )
    if commands != expected:
        raise ContractError(
            f"round6-benchmark must fail closed and execute acceptance plus extract/full-route benchmarks: {source}"
        )
    round6_regression_commands = tuple(
        " ".join(line.split())
        for line in recipes.get("round6-regression", "").splitlines()
        if line.strip()
    )
    plugin_gate_indexes = [
        index
        for index, command in enumerate(round6_regression_commands)
        if "required round-six plugin regression" in command
    ]
    required_wrapper_audit_tests = (
        "TestBalancedAuditOnWrapperOnlyCounterFastPath",
        "TestWrapperAuditFastPathPreservesSecurityEvents",
        "TestBalancedAuditOnTrustedUserWrapperPersists",
        "TestBalancedAuditOnWrapperOnlyAllocationAcceptance",
    )
    if len(plugin_gate_indexes) != 1:
        raise ContractError(
            "round6-regression must retain one fail-closed plugin regression gate"
        )
    plugin_gate_index = plugin_gate_indexes[0]
    plugin_gate = round6_regression_commands[plugin_gate_index]
    if any(plugin_gate.split().count(test_name) != 1 for test_name in required_wrapper_audit_tests):
        raise ContractError(
            "round6-regression must fail closed on every wrapper audit fast-path regression"
        )
    expected_plugin_execution = (
        '$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -count=1 -v '
        '-run="^($$pattern)$$"'
    )
    if (
        plugin_gate.count("@required=(") != 1
        or "required round-six management regression" in plugin_gate
        or plugin_gate.count(expected_plugin_execution) != 1
        or not plugin_gate.endswith(expected_plugin_execution)
    ):
        raise ContractError(
            "round6-regression must execute the exact fail-closed wrapper audit plugin pattern"
        )
    required_script_commands = (
        "make workflow-lint",
        "make shellcheck-lint",
        "bash -n ./scripts/go-safe-development-test.sh",
        "bash -n ./scripts/cpa-latest-compat.sh",
        "bash -n ./scripts/round9-build-host-images.sh",
        "bash -n ./scripts/round9-host-evidence.sh",
        "python3 -B ./scripts/round9-host-evidence-test.py",
        "python3 -B ./scripts/round9_machine_reports_test.py",
        "python3 -B ./scripts/round9_host_evidence_contract_test.py",
        "python3 -B ./scripts/round9_external_evaluation_contract_test.py",
        "python3 -B ./scripts/round9_independent_audit_contract_test.py",
        "python3 -B ./scripts/round6_safe_gate_contract.py --root .",
        "./scripts/check-production-health-test.sh",
        "GO=$(GO) ./scripts/create-store-archive-test.sh",
        "./scripts/generate-hmac-key-test.sh",
    )
    round6_commands = tuple(
        " ".join(line.split())
        for line in recipes.get("round6-script-test", "").splitlines()
        if line.strip()
    )
    positions: list[int] = []
    for command in required_script_commands:
        matches = [
            index for index, actual in enumerate(round6_commands) if actual == command
        ]
        if len(matches) != 1:
            raise ContractError(
                f"round6-script-test must reach the active reviewed script gate: {command}"
            )
        positions.append(matches[0])
    if positions != sorted(positions):
        raise ContractError(
            "round6-script-test must preserve the active reviewed script-gate order"
        )
    retired_markers = (
        "round6-candidate-artifacts",
        "round6-rc-artifacts",
        "round8-host",
        "release-candidate-contract",
        "verify-external-release-attestation",
        "release-doc-consistency",
    )
    if any(marker in command for marker in retired_markers for command in round6_commands):
        raise ContractError(
            "round6-script-test must not execute retired candidate, Round 8, or release gates"
        )


def dotted_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else None
    return None


def literal_command(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)):
        values: list[str] = []
        for element in node.elts:
            if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                return None
            values.append(element.value)
        return shlex.join(values)
    return None


PYTHON_SUBPROCESS_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
)
PYTHON_INDIRECT_EXECUTION_CALLS = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "importlib.import_module",
        "os.popen",
        "os.system",
        "pty.spawn",
        "runpy.run_module",
        "runpy.run_path",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "__import__",
        "builtins.__import__",
        "builtins.compile",
        "builtins.eval",
        "builtins.exec",
        "__builtins__.__import__",
        "__builtins__.compile",
        "__builtins__.eval",
        "__builtins__.exec",
    }
)
PYTHON_EXECUTION_MODULES = frozenset(
    {
        "asyncio",
        "builtins",
        "__builtins__",
        "importlib",
        "operator",
        "os",
        "pty",
        "runpy",
        "subprocess",
        "sys",
    }
)


def python_execution_primitive_reason(
    tree: ast.Module,
    aliases: dict[str, str],
    *,
    reviewed_reference_ids: set[int] | frozenset[int] = frozenset(),
) -> str | None:
    """Return a reason for indirect or non-reviewed Python process dispatch."""

    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }

    def literal_string(node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant) and type(node.value) is str:
            return node.value
        return None

    def subscript_key(node: ast.Subscript) -> str | None:
        return literal_string(node.slice)

    def execution_module_expression(node: ast.AST) -> str | None:
        direct = dotted_name(node, aliases)
        if direct in PYTHON_EXECUTION_MODULES:
            return direct
        if not isinstance(node, ast.Subscript):
            return None
        key = subscript_key(node)
        if key not in PYTHON_EXECUTION_MODULES:
            return None
        namespace = node.value
        if (
            isinstance(namespace, ast.Call)
            and dotted_name(namespace.func, aliases)
            in {"globals", "builtins.globals", "locals", "builtins.locals"}
            and not namespace.args
            and not namespace.keywords
        ):
            return key
        if dotted_name(namespace, aliases) == "sys.modules":
            return key
        return None

    def dangerous_name(name: str | None, *, include_run: bool = False) -> bool:
        if not name:
            return False
        if name in PYTHON_INDIRECT_EXECUTION_CALLS:
            return True
        if include_run and name == "subprocess.run":
            return True
        return name.startswith(("os.exec", "os.spawn", "os.posix_spawn")) or name.endswith(
            (".subprocess_exec", ".subprocess_shell")
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted_name(node.func, aliases)
            if isinstance(node.func, ast.Attribute):
                owner = execution_module_expression(node.func.value)
                if owner is not None:
                    name = f"{owner}.{node.func.attr}"
            if dangerous_name(name):
                return f"indirect Python execution primitive is forbidden: {name}"
            if name in {"getattr", "builtins.getattr"} and node.args:
                target = dotted_name(node.args[0], aliases)
                if target in {"asyncio", "importlib", "os", "pty", "runpy", "subprocess"}:
                    attribute = (
                        node.args[1].value
                        if len(node.args) >= 2
                        and isinstance(node.args[1], ast.Constant)
                        and type(node.args[1].value) is str
                        else None
                    )
                    full_name = f"{target}.{attribute}" if attribute is not None else None
                    if attribute is None or dangerous_name(full_name, include_run=True):
                        return "dynamic execution-module getattr is forbidden"
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"__getattr__", "__getattribute__"}
                and execution_module_expression(node.func.value) is not None
            ):
                attribute = literal_string(node.args[0] if node.args else None)
                if attribute is None or dangerous_name(
                    f"{execution_module_expression(node.func.value)}.{attribute}",
                    include_run=True,
                ):
                    return "execution-module dynamic attribute lookup is forbidden"
            if name in {"vars", "builtins.vars"} and node.args:
                target = dotted_name(node.args[0], aliases)
                if target in {"asyncio", "importlib", "os", "pty", "runpy", "subprocess"}:
                    return "execution-module vars lookup is forbidden"
        elif isinstance(node, ast.Subscript):
            module = execution_module_expression(node)
            if module is not None and dotted_name(node, aliases) is None:
                return f"execution-module namespace lookup is forbidden: {module}"
            value = node.value
            if (
                isinstance(value, ast.Attribute)
                and value.attr == "__dict__"
                and dotted_name(value.value, aliases)
                in {"asyncio", "importlib", "os", "pty", "runpy", "subprocess"}
            ):
                return "execution-module __dict__ lookup is forbidden"

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        module = execution_module_expression(node)
        if module is None:
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.Attribute) and parent.value is node:
            continue
        if isinstance(parent, ast.Call) and parent.args and parent.args[0] is node:
            accessor = dotted_name(parent.func, aliases)
            attribute = literal_string(parent.args[1] if len(parent.args) >= 2 else None)
            if accessor in {
                "getattr",
                "builtins.getattr",
                "hasattr",
                "builtins.hasattr",
            } and attribute is not None and not dangerous_name(
                f"{module}.{attribute}", include_run=True
            ):
                continue
        return f"execution module object may not be stored or passed indirectly: {module}"

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Attribute, ast.Name)):
            continue
        if id(node) in reviewed_reference_ids:
            continue
        name = dotted_name(node, aliases)
        if not dangerous_name(name, include_run=True):
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.Call) and parent.func is node:
            continue
        if isinstance(parent, ast.Attribute) and parent.value is node:
            continue
        return f"execution primitive may not be stored or passed indirectly: {name}"
    return None


def round9_eval_subprocess_function_contract(
    text: str, source: Path
) -> tuple[int, str]:
    """Freeze the complete functions that own Round 9 evaluator subprocess calls."""

    try:
        tree = ast.parse(text, filename=str(source))
    except SyntaxError as exc:
        raise ContractError(f"cannot parse reviewed Round 9 evaluator source {source}: {exc}") from exc
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    subprocess_names = {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
    functions: dict[int, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    call_count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func, aliases)
        if name not in subprocess_names:
            continue
        if name != "subprocess.run":
            raise ContractError(
                f"Round 9 evaluator may use only subprocess.run in reviewed source: {source}"
            )
        if any(
            keyword.arg == "shell"
            and not (
                isinstance(keyword.value, ast.Constant)
                and type(keyword.value.value) is bool
                and keyword.value.value is False
            )
            for keyword in node.keywords
        ):
            raise ContractError(f"Round 9 evaluator shell dispatch is forbidden: {source}")
        if any(keyword.arg == "cwd" for keyword in node.keywords):
            raise ContractError(f"Round 9 evaluator subprocess cwd is forbidden: {source}")
        argument = node.args[0] if node.args else next(
            (keyword.value for keyword in node.keywords if keyword.arg in {"args", "cmd"}),
            None,
        )
        if argument is None:
            raise ContractError(f"Round 9 evaluator subprocess command is missing: {source}")
        enclosing = parents.get(node)
        while enclosing is not None and not isinstance(
            enclosing, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            enclosing = parents.get(enclosing)
        if not isinstance(enclosing, (ast.FunctionDef, ast.AsyncFunctionDef)):
            raise ContractError(
                f"Round 9 evaluator module-level subprocess is forbidden: {source}"
            )
        functions[id(enclosing)] = enclosing
        call_count += 1

    lines = text.splitlines(keepends=True)
    records: list[str] = []
    for function in sorted(
        functions.values(), key=lambda item: (item.lineno, item.col_offset, item.name)
    ):
        if function.end_lineno is None:
            raise ContractError(f"cannot bound reviewed Round 9 evaluator function: {source}")
        names = [function.name]
        parent = parents.get(function)
        while parent is not None:
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(parent.name)
            parent = parents.get(parent)
        segment = "".join(lines[function.lineno - 1 : function.end_lineno])
        records.append(".".join(reversed(names)) + "\0" + segment)
    payload = "\0\0".join(records).encode("utf-8")
    return call_count, hashlib.sha256(payload).hexdigest()


def round9_machine_report_command_function_ast_contract(
    text: str, source: Path
) -> tuple[int, str]:
    try:
        tree = ast.parse(text, filename=str(source))
    except SyntaxError as exc:
        raise ContractError(f"cannot parse Round 9 machine-report generator {source}: {exc}") from exc
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in {"git_output", "run_command"}
    ]
    functions.sort(key=lambda node: (node.lineno, node.name))
    # CPython adds fields to FunctionDef over time, so ast.dump() is not a
    # stable CI identity across supported Python minors.  The parsed source
    # spans keep the structural owner check while remaining byte-deterministic.
    lines = text.splitlines(keepends=True)
    payload = "\0\0".join(
        function.name
        + "\0"
        + "".join(lines[function.lineno - 1 : function.end_lineno])
        for function in functions
    ).encode("utf-8")
    return len(functions), hashlib.sha256(payload).hexdigest()


def round9_exact_function(
    tree: ast.Module,
    name: str,
    source: Path,
    *,
    class_name: str | None = None,
) -> ast.FunctionDef:
    if class_name is None:
        candidates = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ]
    else:
        classes = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        ]
        if len(classes) != 1:
            raise ContractError(
                f"reviewed Round 9 evaluator class differs in {source}: {class_name}"
            )
        candidates = [
            node
            for node in classes[0].body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ]
    if len(candidates) != 1:
        owner = f"{class_name}.{name}" if class_name else name
        raise ContractError(f"reviewed Round 9 evaluator function differs in {source}: {owner}")
    return candidates[0]


def round9_expression_dump(expression: str) -> str:
    return ast.dump(ast.parse(expression, mode="eval").body, include_attributes=False)


def round9_statement_dump(statement: str) -> str:
    parsed = ast.parse(statement).body
    if len(parsed) != 1:
        raise AssertionError("reviewed Round 9 statement must parse exactly once")
    return ast.dump(parsed[0], include_attributes=False)


def round9_direct_assignment(
    body: list[ast.stmt], target: str, expected_expression: str, source: Path, label: str
) -> tuple[int, ast.Assign]:
    matches = [
        (index, node)
        for index, node in enumerate(body)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == target
    ]
    if len(matches) != 1 or ast.dump(
        matches[0][1].value, include_attributes=False
    ) != round9_expression_dump(expected_expression):
        raise ContractError(f"reviewed Round 9 evaluator {label} differs in {source}")
    return matches[0]


def round9_require_next_statement(
    body: list[ast.stmt], index: int, expected_statement: str, source: Path, label: str
) -> None:
    if index + 1 >= len(body) or ast.dump(
        body[index + 1], include_attributes=False
    ) != round9_statement_dump(expected_statement):
        raise ContractError(f"reviewed Round 9 evaluator {label} differs in {source}")


def validate_round9_eval_import_and_primitive_contract(
    tree: ast.Module, source: Path
) -> None:
    execution_modules = {"asyncio", "importlib", "os", "pty", "runpy", "subprocess"}
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
                if alias.name in execution_modules and alias.asname is not None:
                    raise ContractError(
                        f"Round 9 evaluator execution-module alias is forbidden in {source}: {alias.name}"
                    )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            if node.module in execution_modules:
                raise ContractError(
                    f"Round 9 evaluator execution-module from-import is forbidden in {source}: {node.module}"
                )
def validate_round9_eval_broker_subprocess_structure(
    tree: ast.Module, source: Path
) -> None:
    verify = round9_exact_function(tree, "verify_phase1_assets", source)
    loops = [
        node
        for node in verify.body
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Name)
        and node.target.id == "name"
        and ast.dump(node.iter, include_attributes=False)
        == round9_expression_dump("sorted(ARTIFACT_NAMES)")
    ]
    if len(loops) != 1 or loops[0].orelse or len(loops[0].body) != 3:
        raise ContractError(f"reviewed Round 9 evaluator attestation loop differs in {source}")
    loop = loops[0]
    command_index, _ = round9_direct_assignment(
        loop.body,
        "command",
        '[str(config["_gh"]), "attestation", "verify", str(output / name), '
        '"--repo", args.repository, "--signer-workflow", '
        'f"{args.repository}/{RELEASE_WORKFLOW}", "--signer-digest", args.commit, '
        '"--source-ref", f"refs/tags/{TAG}", "--source-digest", args.commit]',
        source,
        "GitHub attestation argv",
    )
    completed_index, _ = round9_direct_assignment(
        loop.body,
        "completed",
        "subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, env=environment, check=False, timeout=120)",
        source,
        "GitHub attestation subprocess",
    )
    if (command_index, completed_index) != (0, 1):
        raise ContractError(f"reviewed Round 9 evaluator attestation order differs in {source}")
    round9_require_next_statement(
        loop.body,
        completed_index,
        'if completed.returncode != 0:\n    fail(f"GitHub attestation verification failed for {name}")',
        source,
        "GitHub attestation result consumption",
    )

    runner = round9_exact_function(tree, "run_external_evaluator", source)
    decrypt_index, _ = round9_direct_assignment(
        runner.body,
        "decrypt",
        '[str(config["_age"]), "--decrypt", "--identity", '
        'config["corpus"]["age_identity"], "--output", str(decrypted_archive), str(encrypted)]',
        source,
        "age decrypt argv",
    )
    completed_index, _ = round9_direct_assignment(
        runner.body,
        "completed",
        "subprocess.run(decrypt, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, env=minimal_subprocess_env(home=str(work)), "
        "check=False, timeout=120)",
        source,
        "age decrypt subprocess",
    )
    if completed_index != decrypt_index + 1:
        raise ContractError(f"reviewed Round 9 evaluator decrypt order differs in {source}")
    round9_require_next_statement(
        runner.body,
        completed_index,
        'if completed.returncode != 0:\n    fail("age failed to decrypt the independent corpus")',
        source,
        "age decrypt result consumption",
    )
    adapter_command_index, _ = round9_direct_assignment(
        runner.body,
        "adapter_command",
        '[str(config["_sandbox_adapter"]), "start", "--config", '
        'str(config["_sandbox_adapter_config"]), "--candidate-so", str(candidate_so), '
        '"--work", str(adapter_work), "--challenge", args.challenge, "--output", str(descriptor)]',
        source,
        "sandbox start argv",
    )

    tries = [node for node in runner.body if isinstance(node, ast.Try)]
    if len(tries) != 1 or tries[0].handlers or tries[0].orelse:
        raise ContractError(f"reviewed Round 9 evaluator lifecycle try/finally differs in {source}")
    lifecycle = tries[0]
    if runner.body.index(lifecycle) <= adapter_command_index:
        raise ContractError(f"reviewed Round 9 evaluator lifecycle order differs in {source}")
    adapter_index, _ = round9_direct_assignment(
        lifecycle.body,
        "adapter",
        "subprocess.run(adapter_command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, env=minimal_subprocess_env(home=str(adapter_work)), "
        "check=False, timeout=600)",
        source,
        "sandbox start subprocess",
    )
    round9_require_next_statement(
        lifecycle.body,
        adapter_index,
        'if adapter.returncode != 0:\n    fail("root-owned CPA sandbox adapter failed")',
        source,
        "sandbox start result consumption",
    )
    evaluator_command_index, _ = round9_direct_assignment(
        lifecycle.body,
        "evaluator_command",
        '[str(config["_evaluator"]), "--corpus-root", str(corpus_root), "--signed-manifest", '
        'str(corpus_root / "bundle-manifest.signed.json"), "--author-public-key", '
         'config["corpus"]["author_public_key"], "--author-key-id", '
         'config["identities"]["author_key_id"], "--bundle-sha256", corpus["bundle_sha256"], '
         '"--public-corpus-root", str(public_root), "--public-development-evidence", '
         'str(public_evidence_path), '
         '"--sandbox-descriptor", str(descriptor), "--expected-candidate-so-sha256", '
        'candidate["so_sha256"], "--expected-core-sha256", '
        'config["identities"]["core_sha256"], "--challenge", args.challenge, "--output", '
        'str(aggregate_path), "--audit-expectations-output", str(expectations_path)]',
        source,
        "external evaluator argv",
    )
    evaluator_index, _ = round9_direct_assignment(
        lifecycle.body,
        "evaluator",
        "subprocess.run(evaluator_command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, env=minimal_subprocess_env(home=str(work)), "
        "check=False, timeout=7200)",
        source,
        "external evaluator subprocess",
    )
    if evaluator_index != evaluator_command_index + 1:
        raise ContractError(f"reviewed Round 9 external evaluator order differs in {source}")
    round9_require_next_statement(
        lifecycle.body,
        evaluator_index,
        'if evaluator.returncode != 0:\n    fail("external evaluator failed")',
        source,
        "external evaluator result consumption",
    )
    finalized_index, _ = round9_direct_assignment(
        lifecycle.body,
        "finalized",
        'subprocess.run([str(config["_sandbox_adapter"]), "finalize", "--config", '
        'str(config["_sandbox_adapter_config"]), "--work", str(adapter_work), "--descriptor", '
        'str(descriptor), "--expectations", str(expectations_path), "--output", str(finalize_path)], '
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, "
        "env=minimal_subprocess_env(home=str(adapter_work)), check=False, timeout=1200)",
        source,
        "sandbox finalize subprocess",
    )
    round9_require_next_statement(
        lifecycle.body,
        finalized_index,
        'if finalized.returncode != 0:\n    fail("root-owned CPA sandbox post-evaluation finalize failed")',
        source,
        "sandbox finalize result consumption",
    )
    if len(lifecycle.finalbody) != 2:
        raise ContractError(f"reviewed Round 9 evaluator cleanup block differs in {source}")
    cleanup_index, _ = round9_direct_assignment(
        lifecycle.finalbody,
        "cleanup",
        'subprocess.run([str(config["_sandbox_adapter"]), "stop", "--config", '
        'str(config["_sandbox_adapter_config"]), "--work", str(adapter_work)], '
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, "
        "env=minimal_subprocess_env(home=str(adapter_work)), check=False, timeout=600)",
        source,
        "sandbox cleanup subprocess",
    )
    round9_require_next_statement(
        lifecycle.finalbody,
        cleanup_index,
        'if cleanup.returncode != 0:\n    fail("root-owned CPA sandbox adapter cleanup failed")',
        source,
        "sandbox cleanup result consumption",
    )


def validate_round9_eval_core_subprocess_structure(
    tree: ast.Module, source: Path
) -> None:
    specifications = (
        (
            "openssl_sign",
            "def openssl_sign(payload: bytes, private_key: Path, openssl: str = \"openssl\") -> bytes:\n    pass\n",
            '[openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key), '
            '"-in", str(payload_path), "-out", str(signature_path)]',
            "subprocess.run(command, capture_output=True, env=openssl_subprocess_env(), "
            "check=False, timeout=30)",
            'if completed.returncode != 0:\n    raise ContractError("OpenSSL failed to sign the evaluator payload")',
        ),
        (
            "openssl_verify",
            "def openssl_verify(payload: bytes, signature: bytes, public_key: Path, "
            "openssl: str = \"openssl\") -> None:\n    pass\n",
            '[openssl, "pkeyutl", "-verify", "-pubin", "-rawin", "-inkey", '
            'str(public_key), "-in", str(payload_path), "-sigfile", str(signature_path)]',
            "subprocess.run(command, capture_output=True, env=openssl_subprocess_env(), "
            "check=False, timeout=30)",
            'if completed.returncode != 0:\n    raise ContractError("external evaluator signature verification failed")',
        ),
    )
    for function_name, signature, command, call, guard in specifications:
        function = round9_exact_function(tree, function_name, source)
        expected = ast.parse(signature).body[0]
        if not isinstance(expected, ast.FunctionDef) or ast.dump(
            function.args, include_attributes=False
        ) != ast.dump(expected.args, include_attributes=False):
            raise ContractError(
                f"reviewed Round 9 evaluator OpenSSL signature differs in {source}: {function_name}"
            )
        with_nodes = [node for node in function.body if isinstance(node, ast.With)]
        if len(with_nodes) != 1:
            raise ContractError(
                f"reviewed Round 9 evaluator OpenSSL temporary scope differs in {source}: {function_name}"
            )
        body = with_nodes[0].body
        command_index, _ = round9_direct_assignment(
            body, "command", command, source, f"{function_name} argv"
        )
        completed_index, _ = round9_direct_assignment(
            body, "completed", call, source, f"{function_name} subprocess"
        )
        if completed_index != command_index + 1:
            raise ContractError(
                f"reviewed Round 9 evaluator OpenSSL order differs in {source}: {function_name}"
            )
        round9_require_next_statement(
            body,
            completed_index,
            guard,
            source,
            f"{function_name} result consumption",
        )


def validate_round9_eval_key_test_subprocess_structure(
    tree: ast.Module, source: Path, *, class_name: str
) -> None:
    function = round9_exact_function(tree, "setUp", source, class_name=class_name)
    expected = ast.parse("def setUp(self) -> None:\n    pass\n").body[0]
    if not isinstance(expected, ast.FunctionDef) or ast.dump(
        function.args, include_attributes=False
    ) != ast.dump(expected.args, include_attributes=False):
        raise ContractError(f"reviewed Round 9 evaluator key-test signature differs in {source}")
    private_index, _ = round9_direct_assignment(
        function.body,
        "private_key",
        'subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519"], '
        "check=True, capture_output=True).stdout",
        source,
        "test private-key argv/result",
    )
    public_index, _ = round9_direct_assignment(
        function.body,
        "public_key",
        'subprocess.run(["openssl", "pkey", "-pubout"], input=private_key, '
        "check=True, capture_output=True).stdout",
        source,
        "test public-key argv/result",
    )
    if public_index <= private_index:
        raise ContractError(f"reviewed Round 9 evaluator key-test order differs in {source}")


def validate_round9_eval_adapter_runner_structure(
    tree: ast.Module, source: Path
) -> set[int]:
    allowed_runner_defaults = (
        "run_command",
        "docker",
        "inspect_image",
        "verify_images",
        "verify_local_docker",
        "published_port",
        "inspect_container",
        "run_runtime_preflight",
        "finalize_evaluation",
        "verify_cleanup_daemon",
        "cleanup_exact_name_absent",
        "cleanup",
        "start",
    )
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in allowed_runner_defaults
    }
    if set(functions) != set(allowed_runner_defaults):
        raise ContractError(f"Round 9 evaluator adapter runner owners differ in {source}")
    reviewed_references: set[int] = set()
    for name in allowed_runner_defaults:
        function = functions[name]
        parameters: list[tuple[ast.arg, ast.expr | None]] = []
        positional_defaults = [None] * (len(function.args.args) - len(function.args.defaults)) + list(
            function.args.defaults
        )
        parameters.extend(zip(function.args.args, positional_defaults))
        parameters.extend(zip(function.args.kwonlyargs, function.args.kw_defaults))
        runner_parameters = [item for item in parameters if item[0].arg == "runner"]
        if len(runner_parameters) != 1:
            raise ContractError(f"Round 9 evaluator adapter runner signature differs in {source}: {name}")
        argument, default = runner_parameters[0]
        if not (
            isinstance(argument.annotation, ast.Name)
            and argument.annotation.id == "CommandRunner"
            and isinstance(default, ast.Attribute)
            and isinstance(default.value, ast.Name)
            and default.value.id == "subprocess"
            and default.attr == "run"
        ):
            raise ContractError(f"Round 9 evaluator adapter runner default differs in {source}: {name}")
        reviewed_references.add(id(default))
    all_run_references = {
        id(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "subprocess"
        and node.attr == "run"
    }
    if all_run_references != reviewed_references:
        raise ContractError(f"Round 9 evaluator adapter subprocess.run references differ in {source}")

    run_command = functions["run_command"]
    expected_run_command = ast.parse(
        "def run_command(\n"
        "    command: Sequence[str],\n"
        "    label: str,\n"
        "    *,\n"
        "    timeout: float = 60,\n"
        "    check: bool = True,\n"
        "    runner: CommandRunner = subprocess.run,\n"
        ") -> subprocess.CompletedProcess[bytes]:\n"
        "    try:\n"
        "        completed = runner(\n"
        "            list(command),\n"
        "            stdin=subprocess.DEVNULL,\n"
        "            stdout=subprocess.PIPE,\n"
        "            stderr=subprocess.PIPE,\n"
        "            check=False,\n"
        "            timeout=timeout,\n"
        "            env={\"PATH\": \"/usr/bin:/bin\", \"HOME\": \"/tmp\"},\n"
        "        )\n"
        "    except (OSError, subprocess.SubprocessError) as exc:\n"
        "        raise AdapterError(f\"{label} failed without exposing command output\") from exc\n"
        "    if check and completed.returncode != 0:\n"
        "        fail(f\"{label} failed with exit={completed.returncode}\")\n"
        "    if len(completed.stdout) > 4_194_304 or len(completed.stderr) > 4_194_304:\n"
        "        fail(f\"{label} output exceeds the reviewed bound\")\n"
        "    return completed\n"
    ).body[0]
    docker = functions["docker"]
    expected_docker = ast.parse(
        "def docker(\n"
        "    config: dict[str, Any],\n"
        "    arguments: Sequence[str],\n"
        "    label: str,\n"
        "    *,\n"
        "    timeout: float = 60,\n"
        "    check: bool = True,\n"
        "    runner: CommandRunner = subprocess.run,\n"
        ") -> subprocess.CompletedProcess[bytes]:\n"
        "    return run_command(\n"
        "        [str(config[\"_docker\"]), *arguments],\n"
        "        label,\n"
        "        timeout=timeout,\n"
        "        check=check,\n"
        "        runner=runner,\n"
        "    )\n"
    ).body[0]
    if (
        not isinstance(expected_run_command, ast.FunctionDef)
        or ast.dump(run_command, include_attributes=False)
        != ast.dump(expected_run_command, include_attributes=False)
        or not isinstance(expected_docker, ast.FunctionDef)
        or ast.dump(docker, include_attributes=False)
        != ast.dump(expected_docker, include_attributes=False)
    ):
        raise ContractError(f"Round 9 evaluator adapter command chain differs in {source}")
    runner_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "runner"
    ]
    if len(runner_calls) != 1 or runner_calls[0] not in set(ast.walk(run_command)):
        raise ContractError(f"Round 9 evaluator adapter indirect runner call differs in {source}")
    return reviewed_references


def reviewed_round9_eval_execution_reference_ids(
    tree: ast.Module, source: Path, root: Path
) -> set[int]:
    root = root.resolve()
    safe_source = assert_safe_repo_path(source, root)
    relative = safe_source.relative_to(root).as_posix()
    if relative == "tools/round9-eval/cag_round9_cpa_sandbox_adapter.py":
        return validate_round9_eval_adapter_runner_structure(tree, source)
    return set()


def reviewed_round9_eval_dynamic_call_ids(
    tree: ast.Module, source: Path, root: Path
) -> set[int]:
    root = root.resolve()
    safe_source = assert_safe_repo_path(source, root)
    relative = safe_source.relative_to(root).as_posix()
    if relative not in ROUND9_EVAL_REVIEWED_SCRIPT_SHA256:
        return set()
    validate_round9_eval_import_and_primitive_contract(tree, source)
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and dotted_name(node.func, aliases) in PYTHON_SUBPROCESS_CALLS
    ]
    if any(dotted_name(node.func, aliases) != "subprocess.run" for node in calls):
        raise ContractError(f"Round 9 evaluator non-run subprocess is forbidden: {source}")
    expected_count = ROUND9_EVAL_SUBPROCESS_FUNCTION_CONTRACT[relative][0]
    if len(calls) != expected_count:
        raise ContractError(f"Round 9 evaluator subprocess count differs: {source}")
    if relative == "tools/round9-eval/cag_round9_eval_broker.py":
        validate_round9_eval_broker_subprocess_structure(tree, source)
    elif relative == "tools/round9-eval/round9_eval_core.py":
        validate_round9_eval_core_subprocess_structure(tree, source)
    elif relative == "tools/round9-eval/round9_eval_core_test.py":
        validate_round9_eval_key_test_subprocess_structure(
            tree, source, class_name="Round9EvalCoreTest"
        )
    elif relative == "tools/round9-eval/cag_round9_external_evaluator_test.py":
        validate_round9_eval_key_test_subprocess_structure(
            tree, source, class_name="ExternalEvaluatorTest"
        )
    elif calls:
        raise ContractError(f"Round 9 evaluator unexpected subprocess owner: {source}")
    return {id(node) for node in calls}


def round9_host_evidence_command_function_contract(
    text: str, source: Path
) -> tuple[int, int, str]:
    """Freeze every function that owns the Round 9 Host command graph."""

    try:
        tree = ast.parse(text, filename=str(source))
    except SyntaxError as exc:
        raise ContractError(f"cannot parse reviewed Round 9 Host source {source}: {exc}") from exc
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    subprocess_names = {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
    helper_names = {"run_command", "docker"}
    functions: dict[int, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    subprocess_count = 0
    helper_count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func, aliases)
        if name not in subprocess_names | helper_names:
            continue
        if name in subprocess_names:
            if name != "subprocess.run":
                raise ContractError(
                    f"Round 9 Host may use only subprocess.run in reviewed source: {source}"
                )
            subprocess_count += 1
        else:
            helper_count += 1
        enclosing = parents.get(node)
        while enclosing is not None and not isinstance(
            enclosing, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            enclosing = parents.get(enclosing)
        if not isinstance(enclosing, (ast.FunctionDef, ast.AsyncFunctionDef)):
            raise ContractError(f"Round 9 Host module-level command dispatch is forbidden: {source}")
        functions[id(enclosing)] = enclosing

    lines = text.splitlines(keepends=True)
    records: list[str] = []
    for function in sorted(
        functions.values(), key=lambda item: (item.lineno, item.col_offset, item.name)
    ):
        if function.end_lineno is None:
            raise ContractError(f"cannot bound reviewed Round 9 Host function: {source}")
        names = [function.name]
        parent = parents.get(function)
        while parent is not None:
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(parent.name)
            parent = parents.get(parent)
        segment = "".join(lines[function.lineno - 1 : function.end_lineno])
        records.append(".".join(reversed(names)) + "\0" + segment)
    payload = "\0\0".join(records).encode("utf-8")
    return subprocess_count, helper_count, hashlib.sha256(payload).hexdigest()


def reviewed_round9_host_evidence_dynamic_call_ids(
    tree: ast.Module, source: Path, root: Path
) -> set[int]:
    """Admit only the exact dynamic argv runner in the frozen Round 9 Host script."""

    root = root.resolve()
    safe_source = assert_safe_repo_path(source, root)
    if safe_source.relative_to(root).as_posix() != ROUND9_HOST_EVIDENCE_SCRIPT:
        return set()
    contract_error = "reviewed Round 9 Host subprocess contract differs in " + str(source)
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "run_command"
    ]
    if len(functions) != 1 or not isinstance(functions[0], ast.FunctionDef):
        raise ContractError(contract_error)
    function = functions[0]
    if function.decorator_list:
        raise ContractError(contract_error)
    expected_arguments = ast.parse(
        "def run_command(args: list[str], *, label: str, timeout: float = 120, "
        "check: bool = True):\n    pass\n"
    ).body[0]
    if not isinstance(expected_arguments, ast.FunctionDef) or ast.dump(
        function.args, include_attributes=False
    ) != ast.dump(expected_arguments.args, include_attributes=False):
        raise ContractError(contract_error)

    subprocess_imports = [
        alias
        for statement in tree.body
        if isinstance(statement, ast.Import)
        for alias in statement.names
        if alias.name == "subprocess"
    ]
    if len(subprocess_imports) != 1 or subprocess_imports[0].asname is not None:
        raise ContractError(contract_error)
    if any(
        isinstance(node, ast.ImportFrom) and node.module == "subprocess"
        for node in ast.walk(tree)
    ):
        raise ContractError(contract_error)

    subprocess_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr
        in {
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "getstatusoutput",
        }
    ]
    if len(subprocess_calls) != 1:
        raise ContractError(contract_error)
    call = subprocess_calls[0]
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    enclosing = parents.get(call)
    while enclosing is not None and not isinstance(
        enclosing, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        enclosing = parents.get(enclosing)
    expected_call = ast.parse(
        "subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, "
        "timeout=timeout, check=False)",
        mode="eval",
    ).body
    if enclosing is not function or ast.dump(
        call, include_attributes=False
    ) != ast.dump(expected_call, include_attributes=False):
        raise ContractError(contract_error)
    docker_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "docker"
    ]
    expected_docker = ast.parse(
        "def docker(\n"
        "    args: list[str], *, label: str, timeout: float = 120, check: bool = True\n"
        ") -> subprocess.CompletedProcess[bytes]:\n"
        "    return run_command([\"docker\", *args], label=label, timeout=timeout, check=check)\n"
    ).body[0]
    if (
        len(docker_functions) != 1
        or not isinstance(expected_docker, ast.FunctionDef)
        or ast.dump(docker_functions[0], include_attributes=False)
        != ast.dump(expected_docker, include_attributes=False)
    ):
        raise ContractError(contract_error)
    return {id(call)}


def reviewed_repository_secret_scan_dynamic_call_ids(
    tree: ast.Module, text: str, source: Path, root: Path
) -> set[int]:
    """Admit only the fixed, non-shell Git inventory in the reviewed scanner."""

    root = root.resolve()
    safe_source = assert_safe_repo_path(source, root)
    relative = safe_source.relative_to(root).as_posix()
    expected_hash = REPOSITORY_SECRET_SCAN_SHA256.get(relative)
    if expected_hash is None:
        return set()
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != expected_hash:
        raise ContractError(
            f"repository secret scanner differs from the reviewed contract: {source}"
        )
    if relative == REPOSITORY_SECRET_SCAN_TEST_SCRIPT:
        return set()

    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "git_visible_paths"
    ]
    if len(functions) != 1 or functions[0].decorator_list:
        raise ContractError(
            f"repository secret scanner Git inventory differs from the reviewed contract: {source}"
        )
    function = functions[0]
    expected_arguments = ast.parse(
        "def git_visible_paths(root: Path) -> list[str]:\n    pass\n"
    ).body[0]
    if not isinstance(expected_arguments, ast.FunctionDef) or ast.dump(
        function.args, include_attributes=False
    ) != ast.dump(expected_arguments.args, include_attributes=False):
        raise ContractError(
            f"repository secret scanner Git inventory differs from the reviewed contract: {source}"
        )

    subprocess_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr
        in {
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "getstatusoutput",
        }
    ]
    if len(subprocess_calls) != 1:
        raise ContractError(
            f"repository secret scanner Git inventory differs from the reviewed contract: {source}"
        )
    call = subprocess_calls[0]
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    enclosing = parents.get(call)
    while enclosing is not None and not isinstance(
        enclosing, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        enclosing = parents.get(enclosing)
    expected_call = ast.parse(
        'subprocess.run(["git", "-C", str(root), "ls-files", "-co", '
        '"--exclude-standard", "-z"], stdin=subprocess.DEVNULL, '
        "capture_output=True, check=False, timeout=30)",
        mode="eval",
    ).body
    if enclosing is not function or ast.dump(
        call, include_attributes=False
    ) != ast.dump(expected_call, include_attributes=False):
        raise ContractError(
            f"repository secret scanner Git inventory differs from the reviewed contract: {source}"
        )
    return {id(call)}


def reviewed_round9_machine_report_test_dynamic_call_ids(
    tree: ast.Module, source: Path, root: Path
) -> set[int]:
    """Admit only the fixed temporary-repository Git helper in its reviewed test."""

    root = root.resolve()
    safe_source = assert_safe_repo_path(source, root)
    if safe_source.relative_to(root).as_posix() != ROUND9_MACHINE_REPORT_TEST_SCRIPT:
        return set()
    contract_error = "reviewed Round 9 machine-report test subprocess contract differs in " + str(
        source
    )
    classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "Round9MachineReportsTest"
    ]
    if len(classes) != 1:
        raise ContractError(contract_error)
    methods = [
        node
        for node in classes[0].body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "git"
    ]
    if len(methods) != 1 or not isinstance(methods[0], ast.FunctionDef):
        raise ContractError(contract_error)
    method = methods[0]
    if len(method.decorator_list) != 1 or not (
        isinstance(method.decorator_list[0], ast.Name)
        and method.decorator_list[0].id == "staticmethod"
    ):
        raise ContractError(contract_error)
    expected_arguments = ast.parse(
        "def git(root: Path, *arguments: str) -> str:\n    pass\n"
    ).body[0]
    if not isinstance(expected_arguments, ast.FunctionDef) or ast.dump(
        method.args, include_attributes=False
    ) != ast.dump(expected_arguments.args, include_attributes=False):
        raise ContractError(contract_error)

    subprocess_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr
        in {
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "getstatusoutput",
        }
    ]
    if len(subprocess_calls) != 1:
        raise ContractError(contract_error)
    call = subprocess_calls[0]
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    enclosing = parents.get(call)
    while enclosing is not None and not isinstance(
        enclosing, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        enclosing = parents.get(enclosing)
    expected_call = ast.parse(
        'subprocess.run(["git", "-C", str(root), *arguments], check=True, '
        "stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)",
        mode="eval",
    ).body
    if enclosing is not method or ast.dump(
        call, include_attributes=False
    ) != ast.dump(expected_call, include_attributes=False):
        raise ContractError(contract_error)
    return {id(call)}


def reviewed_round9_docker_sandbox_dynamic_call_ids(
    tree: ast.Module, source: Path, root: Path
) -> set[int]:
    """Admit only the fixed Docker CLI wrapper in the reviewed sandbox preflight."""

    root = root.resolve()
    safe_source = assert_safe_repo_path(source, root)
    if safe_source.relative_to(root).as_posix() != ROUND9_DOCKER_SANDBOX_SCRIPT:
        return set()
    contract_error = "reviewed Round 9 Docker sandbox subprocess contract differs in " + str(
        source
    )
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_docker"
    ]
    if len(functions) != 1 or not isinstance(functions[0], ast.FunctionDef):
        raise ContractError(contract_error)
    function = functions[0]
    if function.decorator_list:
        raise ContractError(contract_error)
    expected_arguments = ast.parse(
        "def _docker(args: Sequence[str], label: str, timeout: float = 30, "
        "check: bool = True):\n    pass\n"
    ).body[0]
    if not isinstance(expected_arguments, ast.FunctionDef) or ast.dump(
        function.args, include_attributes=False
    ) != ast.dump(expected_arguments.args, include_attributes=False):
        raise ContractError(contract_error)

    subprocess_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr
        in {
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "getstatusoutput",
        }
    ]
    if len(subprocess_calls) != 1:
        raise ContractError(contract_error)
    call = subprocess_calls[0]
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    enclosing = parents.get(call)
    while enclosing is not None and not isinstance(
        enclosing, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        enclosing = parents.get(enclosing)
    expected_call = ast.parse(
        'subprocess.run(["docker", *args], stdout=subprocess.PIPE, '
        "stderr=subprocess.PIPE, timeout=timeout, check=False)",
        mode="eval",
    ).body
    if enclosing is not function or ast.dump(
        call, include_attributes=False
    ) != ast.dump(expected_call, include_attributes=False):
        raise ContractError(contract_error)
    return {id(call)}


def reviewed_round9_git_boundary_dynamic_call_ids(
    tree: ast.Module, source: Path, root: Path
) -> set[int]:
    """Admit only the self-audited, fixed Git path-boundary subprocess call."""

    root = root.resolve()
    safe_source = assert_safe_repo_path(source, root)
    if safe_source.relative_to(root).as_posix() != ROUND6_SAFE_GATE_SCRIPT:
        return set()

    contract_error = (
        "reviewed Round 9 Git boundary subprocess contract differs in " + str(source)
    )
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "validate_round9_independent_git_boundary"
    ]
    if not functions:
        return set()
    if len(functions) != 1 or not isinstance(functions[0], ast.FunctionDef):
        raise ContractError(contract_error)
    function = functions[0]
    if function not in tree.body or function.decorator_list:
        raise ContractError(contract_error)
    arguments = function.args
    if (
        arguments.posonlyargs
        or [argument.arg for argument in arguments.args] != ["root"]
        or arguments.vararg is not None
        or arguments.kwonlyargs
        or arguments.kw_defaults
        or arguments.kwarg is not None
        or arguments.defaults
    ):
        raise ContractError(contract_error)

    subprocess_imports = [
        alias
        for statement in tree.body
        if isinstance(statement, ast.Import)
        for alias in statement.names
        if alias.name == "subprocess"
    ]
    if len(subprocess_imports) != 1 or subprocess_imports[0].asname is not None:
        raise ContractError(contract_error)
    if any(
        isinstance(node, ast.ImportFrom) and node.module == "subprocess"
        for node in ast.walk(tree)
    ):
        raise ContractError(contract_error)

    pathspec_stores = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Store)
        and node.id == "ROUND9_INDEPENDENT_GIT_PATHSPEC"
    ]
    if len(pathspec_stores) != 1:
        raise ContractError(contract_error)
    pathspec_parent = next(
        (
            statement
            for statement in tree.body
            if isinstance(statement, ast.Assign)
            and statement.targets == [pathspec_stores[0]]
        ),
        None,
    )
    if not (
        isinstance(pathspec_parent, ast.Assign)
        and isinstance(pathspec_parent.value, ast.Constant)
        and type(pathspec_parent.value.value) is str
        and pathspec_parent.value.value == ":(glob)testdata/round9-independent-*/**"
    ):
        raise ContractError(contract_error)

    if any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Store)
        and node.id in {"root", "str", "subprocess"}
        for node in ast.walk(function)
    ):
        raise ContractError(contract_error)
    for statement in tree.body:
        if (
            isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and statement is not function
            and statement.name in {"str", "subprocess"}
        ):
            raise ContractError(contract_error)
        if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
            and node.id in {"str", "subprocess"}
            for node in ast.walk(statement)
        ):
            raise ContractError(contract_error)
        if isinstance(statement, (ast.Import, ast.ImportFrom)) and any(
            (alias.asname or alias.name.split(".")[0]) in {"str", "subprocess"}
            and not (alias.name == "subprocess" and alias.asname is None)
            for alias in statement.names
        ):
            raise ContractError(contract_error)
    if any(
        isinstance(node, ast.Attribute)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and isinstance(node.value, ast.Name)
        and node.value.id == "subprocess"
        and node.attr == "run"
        for node in ast.walk(tree)
    ):
        raise ContractError(contract_error)

    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    command_stores = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Store)
        and node.id == "command"
    ]
    if len(command_stores) != 1:
        raise ContractError(contract_error)
    command_assignment = parents.get(command_stores[0])
    if not (
        isinstance(command_assignment, ast.Assign)
        and command_assignment in function.body
        and command_assignment.targets == [command_stores[0]]
        and isinstance(command_assignment.value, ast.List)
    ):
        raise ContractError(contract_error)
    command_elements = command_assignment.value.elts
    if len(command_elements) != 7:
        raise ContractError(contract_error)

    def is_string(node: ast.AST, value: str) -> bool:
        return (
            isinstance(node, ast.Constant)
            and type(node.value) is str
            and node.value == value
        )

    root_string = command_elements[2]
    if not (
        is_string(command_elements[0], "git")
        and is_string(command_elements[1], "-C")
        and isinstance(root_string, ast.Call)
        and isinstance(root_string.func, ast.Name)
        and root_string.func.id == "str"
        and len(root_string.args) == 1
        and isinstance(root_string.args[0], ast.Name)
        and root_string.args[0].id == "root"
        and not root_string.keywords
        and is_string(command_elements[3], "ls-files")
        and is_string(command_elements[4], "-z")
        and is_string(command_elements[5], "--")
        and isinstance(command_elements[6], ast.Name)
        and command_elements[6].id == "ROUND9_INDEPENDENT_GIT_PATHSPEC"
    ):
        raise ContractError(contract_error)

    subprocess_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr in {
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "getstatusoutput",
        }
        and literal_command(
            node.args[0]
            if node.args
            else next(
                (
                    keyword.value
                    for keyword in node.keywords
                    if keyword.arg in {"args", "cmd"}
                ),
                None,
            )
        )
        is None
    ]
    if len(subprocess_calls) != 1:
        raise ContractError(contract_error)
    call = subprocess_calls[0]
    enclosing = parents.get(call)
    while enclosing is not None and not isinstance(
        enclosing, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        enclosing = parents.get(enclosing)
    call_assignment = parents.get(call)
    try_statements = [
        node for node in ast.walk(function) if isinstance(node, ast.Try)
    ]
    if len(try_statements) != 1:
        raise ContractError(contract_error)
    try_statement = try_statements[0]
    if not (
        enclosing is function
        and isinstance(call.func, ast.Attribute)
        and isinstance(call.func.ctx, ast.Load)
        and isinstance(call.func.value, ast.Name)
        and isinstance(call.func.value.ctx, ast.Load)
        and call.func.value.id == "subprocess"
        and call.func.attr == "run"
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Name)
        and isinstance(call.args[0].ctx, ast.Load)
        and call.args[0].id == "command"
        and isinstance(call_assignment, ast.Assign)
        and len(call_assignment.targets) == 1
        and isinstance(call_assignment.targets[0], ast.Name)
        and call_assignment.targets[0].id == "completed"
        and try_statement in function.body
        and try_statement.body == [call_assignment]
        and len(try_statement.handlers) == 1
        and not try_statement.orelse
        and not try_statement.finalbody
        and function.body.index(command_assignment) < function.body.index(try_statement)
    ):
        raise ContractError(contract_error)
    handler = try_statement.handlers[0]
    if not (
        isinstance(handler.type, ast.Attribute)
        and isinstance(handler.type.ctx, ast.Load)
        and isinstance(handler.type.value, ast.Name)
        and isinstance(handler.type.value.ctx, ast.Load)
        and handler.type.value.id == "subprocess"
        and handler.type.attr == "TimeoutExpired"
        and handler.name == "exc"
        and len(handler.body) == 1
        and isinstance(handler.body[0], ast.Raise)
    ):
        raise ContractError(contract_error)
    raise_statement = handler.body[0]
    if not (
        isinstance(raise_statement.exc, ast.Call)
        and isinstance(raise_statement.exc.func, ast.Name)
        and isinstance(raise_statement.exc.func.ctx, ast.Load)
        and raise_statement.exc.func.id == "ContractError"
        and len(raise_statement.exc.args) == 1
        and isinstance(raise_statement.exc.args[0], ast.Constant)
        and type(raise_statement.exc.args[0].value) is str
        and raise_statement.exc.args[0].value
        == "cannot verify the Round 9 independent Git boundary"
        and not raise_statement.exc.keywords
        and isinstance(raise_statement.cause, ast.Name)
        and isinstance(raise_statement.cause.ctx, ast.Load)
        and raise_statement.cause.id == "exc"
    ):
        raise ContractError(contract_error)
    if [keyword.arg for keyword in call.keywords] != [
        "stdin",
        "capture_output",
        "check",
        "timeout",
    ]:
        raise ContractError(contract_error)
    stdin, capture_output, check, timeout = [keyword.value for keyword in call.keywords]
    if not (
        isinstance(stdin, ast.Attribute)
        and isinstance(stdin.ctx, ast.Load)
        and isinstance(stdin.value, ast.Name)
        and isinstance(stdin.value.ctx, ast.Load)
        and stdin.value.id == "subprocess"
        and stdin.attr == "DEVNULL"
        and isinstance(capture_output, ast.Constant)
        and type(capture_output.value) is bool
        and capture_output.value is True
        and isinstance(check, ast.Constant)
        and type(check.value) is bool
        and check.value is False
        and isinstance(timeout, ast.Constant)
        and type(timeout.value) is int
        and timeout.value == 30
    ):
        raise ContractError(contract_error)
    return {id(call)}


def local_python_imports(tree: ast.AST, source: Path, root: Path) -> set[str]:
    result: set[str] = set()
    for node in ast.walk(tree):
        modules: list[tuple[str, int]] = []
        if isinstance(node, ast.Import):
            modules.extend((alias.name, 0) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append((node.module, node.level))
        for module, level in modules:
            relative = Path(*module.split("."))
            bases = [source.parent] if level else [source.parent, root]
            found = False
            for base in bases:
                for candidate in (base / f"{relative}.py", base / relative / "__init__.py"):
                    safe = assert_safe_repo_path(candidate, root)
                    if safe.exists():
                        result.add(safe.relative_to(root).as_posix())
                        found = True
                        break
                if found:
                    break
    return result


def validate_round9_eval_tool_bundle(root: Path) -> set[str]:
    """Validate the exact active evaluator source bundle without executing it."""

    root = root.resolve()
    directory = assert_safe_repo_path(Path("tools/round9-eval"), root)
    actual_python_paths = {
        path.relative_to(root).as_posix()
        for path in directory.glob("*.py")
        if path.is_file() and not path.is_symlink()
    }
    expected_paths = set(ROUND9_EVAL_REVIEWED_SCRIPT_SHA256)
    if actual_python_paths != expected_paths:
        raise ContractError(
            "Round 9 evaluator Python bundle differs from the reviewed path allowlist"
        )
    if set(ROUND9_EVAL_SUBPROCESS_FUNCTION_CONTRACT) != expected_paths:
        raise ContractError(
            "Round 9 evaluator subprocess function contract is incomplete"
        )

    local_imports: set[str] = set()
    for relative in sorted(expected_paths):
        source = root / relative
        text = read_regular_text(source, root)
        actual_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if actual_hash != ROUND9_EVAL_REVIEWED_SCRIPT_SHA256[relative]:
            raise ContractError(
                f"Round 9 evaluator source differs from reviewed SHA-256: {relative}"
            )
        actual_contract = round9_eval_subprocess_function_contract(text, source)
        if actual_contract != ROUND9_EVAL_SUBPROCESS_FUNCTION_CONTRACT[relative]:
            raise ContractError(
                f"Round 9 evaluator subprocess function differs from reviewed contract: {relative}"
            )
        try:
            tree = ast.parse(text, filename=str(source))
        except SyntaxError as exc:
            raise ContractError(f"cannot parse reviewed Round 9 evaluator source {source}: {exc}") from exc
        targets, audited_imports = audit_python_source(text, source, root)
        if targets:
            raise ContractError(
                f"Round 9 evaluator reaches Make targets outside the reviewed Python bundle: {relative}"
            )
        local_imports.update(audited_imports)
    unreviewed_imports = local_imports - expected_paths
    if unreviewed_imports:
        raise ContractError(
            "Round 9 evaluator reaches local imports outside the exact reviewed allowlist: "
            + ", ".join(sorted(unreviewed_imports))
        )
    return expected_paths


def validate_round9_eval_install_script(text: str, source: Path) -> None:
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != ROUND9_EVAL_INSTALL_SCRIPT_SHA256:
        raise ContractError(f"Round 9 evaluator installer differs from reviewed SHA-256: {source}")
    if source.name != "install.sh" or source.parent.name != "round9-eval":
        raise ContractError(f"Round 9 evaluator installer is outside the reviewed path: {source}")
    python_commands = tuple(
        match.group(0).strip()
        for match in re.finditer(r"(?m)^\s*python3[^\n]*", text)
    )
    if python_commands != (
        "python3 -I -B - \\",
        'python3 -I -B -m py_compile "$source"',
        "python3 -I -B - \\",
        "python3 -I -B -m py_compile \\",
    ):
        raise ContractError("Round 9 evaluator installer Python command graph differs")
    if text.count("<<'PY'") != 2 or len(re.findall(r"(?m)^PY$", text)) != 2:
        raise ContractError("Round 9 evaluator installer heredoc boundary differs")
    required_markers = (
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONHOME PYTHONPATH",
        'source_dir="$(cd "${BASH_SOURCE[0]%/*}" && pwd -P)"',
        'repository_root="$(cd "$source_dir/../.." && pwd -P)"',
        'staging_dir="$(mktemp -d /tmp/cag-round9-install.XXXXXXXX)"',
        'command -v "$command" >/dev/null',
        '"$docker_sandbox_source" round9_docker_sandbox.py source <<\'PY\'',
        "/usr/local/libexec/cag-round9-eval-broker",
        "/usr/local/libexec/cag-round9-external-evaluator",
        "/usr/local/libexec/cag-round9-cpa-sandbox",
        "/usr/local/libexec/cag-round9-docker-sandbox",
        "/etc/cag-round9-eval-broker/config.json",
        "/etc/cag-round9-eval-broker/sandbox-adapter.json",
    )
    if any(text.count(marker) < 1 for marker in required_markers):
        raise ContractError("Round 9 evaluator installer fixed-path contract differs")
    fixed_install_blocks = (
        'install -o root -g root -m 0644 \\\n  "$core_source" \\\n  /usr/local/libexec/round9_eval_core.py',
        'install -o root -g root -m 0755 \\\n  "$evaluator_source" \\\n  /usr/local/libexec/cag-round9-external-evaluator',
        'install -o root -g root -m 0755 \\\n  "$broker_source" \\\n  /usr/local/libexec/cag-round9-eval-broker',
        'install -o root -g root -m 0755 \\\n  "$adapter_source" \\\n  /usr/local/libexec/cag-round9-cpa-sandbox',
        'install -o root -g root -m 0755 \\\n  "$docker_sandbox_source" \\\n  /usr/local/libexec/cag-round9-docker-sandbox',
        'install -o root -g root -m 0600 \\\n  "$config_source" \\\n  /etc/cag-round9-eval-broker/config.json',
        'install -o root -g root -m 0600 \\\n  "$adapter_config_source" \\\n  /etc/cag-round9-eval-broker/sandbox-adapter.json',
    )
    if any(text.count(block) != 1 for block in fixed_install_blocks):
        raise ContractError("Round 9 evaluator installer fixed install operation differs")
    shell_only = re.sub(r"<<'PY'\n.*?\nPY", "<<'PY'\nPY", text, flags=re.DOTALL)
    if re.search(r"(?m)^\s*(?:eval|exec|source)\b", shell_only):
        raise ContractError("Round 9 evaluator installer dynamic shell dispatch is forbidden")
    if re.search(r"(?m)^\s*(?:curl|wget|ssh|scp|git|pip|npm|go)\b", shell_only):
        raise ContractError("Round 9 evaluator installer network/package dispatch is forbidden")
    if re.search(r"(?m)(?:^|[;&|]\s*)(?:ba)?sh\s+-c\b", shell_only):
        raise ContractError("Round 9 evaluator installer nested shell dispatch is forbidden")


def validate_round9_host_evidence_test_script(text: str, source: Path) -> None:
    if (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        != ROUND9_HOST_EVIDENCE_TEST_SCRIPT_SHA256
    ):
        raise ContractError(
            f"Round 9 Host evidence test differs from reviewed SHA-256: {source}"
        )
    if source.name != "round9-host-evidence-test.py" or source.parent.name != "scripts":
        raise ContractError(
            f"Round 9 Host evidence test is outside the reviewed path: {source}"
        )
    if (
        round9_eval_subprocess_function_contract(text, source)
        != ROUND9_HOST_EVIDENCE_TEST_SUBPROCESS_CONTRACT
    ):
        raise ContractError(
            f"Round 9 Host evidence test subprocess differs from reviewed contract: {source}"
        )


def validate_round9_host_evidence_script(text: str, source: Path) -> None:
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != ROUND9_HOST_EVIDENCE_SCRIPT_SHA256:
        raise ContractError(
            f"Round 9 Host evidence runner differs from reviewed SHA-256: {source}"
        )
    if source.name != "round9_host_evidence.py" or source.parent.name != "scripts":
        raise ContractError(
            f"Round 9 Host evidence runner is outside the reviewed path: {source}"
        )
    if (
        round9_host_evidence_command_function_contract(text, source)
        != ROUND9_HOST_EVIDENCE_COMMAND_FUNCTION_CONTRACT
    ):
        raise ContractError(
            f"Round 9 Host evidence command functions differ from reviewed contract: {source}"
        )
    try:
        tree = ast.parse(text, filename=str(source))
    except SyntaxError as exc:
        raise ContractError(f"cannot parse reviewed Round 9 Host source {source}: {exc}") from exc
    root = source.parent.parent
    if len(reviewed_round9_host_evidence_dynamic_call_ids(tree, source, root)) != 1:
        raise ContractError(
            f"Round 9 Host evidence subprocess differs from reviewed contract: {source}"
        )


def validate_round9_machine_report_test_script(text: str, source: Path) -> None:
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != ROUND9_MACHINE_REPORT_TEST_SCRIPT_SHA256:
        raise ContractError(
            f"Round 9 machine-report test differs from reviewed SHA-256: {source}"
        )
    if source.name != "round9_machine_reports_test.py" or source.parent.name != "scripts":
        raise ContractError(
            f"Round 9 machine-report test is outside the reviewed path: {source}"
        )
    if (
        round9_eval_subprocess_function_contract(text, source)
        != ROUND9_MACHINE_REPORT_TEST_SUBPROCESS_CONTRACT
    ):
        raise ContractError(
            f"Round 9 machine-report test subprocess function differs from reviewed contract: {source}"
        )
    try:
        tree = ast.parse(text, filename=str(source))
    except SyntaxError as exc:
        raise ContractError(f"cannot parse reviewed Round 9 machine-report test {source}: {exc}") from exc
    if len(
        reviewed_round9_machine_report_test_dynamic_call_ids(
            tree, source, source.parent.parent
        )
    ) != 1:
        raise ContractError(
            f"Round 9 machine-report test subprocess differs from reviewed contract: {source}"
        )


def validate_round9_docker_sandbox_script(text: str, source: Path) -> None:
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != ROUND9_DOCKER_SANDBOX_SCRIPT_SHA256:
        raise ContractError(
            f"Round 9 Docker sandbox differs from reviewed SHA-256: {source}"
        )
    if source.name != "round9_docker_sandbox.py" or source.parent.name != "scripts":
        raise ContractError(f"Round 9 Docker sandbox is outside the reviewed path: {source}")
    if (
        round9_eval_subprocess_function_contract(text, source)
        != ROUND9_DOCKER_SANDBOX_SUBPROCESS_CONTRACT
    ):
        raise ContractError(
            f"Round 9 Docker sandbox subprocess function differs from reviewed contract: {source}"
        )
    try:
        tree = ast.parse(text, filename=str(source))
    except SyntaxError as exc:
        raise ContractError(f"cannot parse reviewed Round 9 Docker sandbox {source}: {exc}") from exc
    if len(
        reviewed_round9_docker_sandbox_dynamic_call_ids(
            tree, source, source.parent.parent
        )
    ) != 1:
        raise ContractError(
            f"Round 9 Docker sandbox subprocess differs from reviewed contract: {source}"
        )


def validate_round9_machine_report_script(text: str, source: Path) -> None:
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != ROUND9_MACHINE_REPORT_SCRIPT_SHA256:
        raise ContractError(
            f"Round 9 machine-report generator differs from the reviewed contract: {source}"
        )
    if source.name != "round9_machine_reports.py" or source.parent.name != "scripts":
        raise ContractError(
            f"Round 9 machine-report generator is outside the reviewed path: {source}"
        )
    if (
        round9_machine_report_command_function_ast_contract(text, source)
        != ROUND9_MACHINE_REPORT_COMMAND_FUNCTION_AST_CONTRACT
    ):
        raise ContractError(
            f"Round 9 machine-report command-owner control flow differs from reviewed contract: {source}"
        )
    try:
        tree = ast.parse(text, filename=str(source))
    except SyntaxError as exc:
        raise ContractError(f"cannot parse Round 9 machine-report generator {source}: {exc}") from exc

    def expression_dump(expression: str) -> str:
        return ast.dump(ast.parse(expression, mode="eval").body, include_attributes=False)

    def statement_dump(statement: str) -> str:
        parsed = ast.parse(statement).body
        if len(parsed) != 1:
            raise AssertionError("reviewed machine-report statement must parse once")
        return ast.dump(parsed[0], include_attributes=False)

    function_nodes = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for name in (
        "git_output",
        "run_command",
        "candidate_identity",
        "development_candidate_identity",
        "public_report",
        "paired_report",
        "audit_report",
    ):
        matches = [node for node in function_nodes if node.name == name]
        if len(matches) != 1 or not isinstance(matches[0], ast.FunctionDef):
            raise ContractError(
                f"Round 9 machine-report command owner differs from reviewed contract: {name}"
            )
        functions[name] = matches[0]
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func, aliases)
        if name in {"eval", "exec", "compile", "os.system", "os.popen"} or (
            name is not None and name.startswith(("os.exec", "os.spawn"))
        ):
            raise ContractError(
                f"Round 9 machine-report dynamic dispatch is forbidden: {name}"
            )
    git_function = functions["git_output"]
    run_function = functions["run_command"]
    if (
        [argument.arg for argument in git_function.args.args] != ["root"]
        or git_function.args.vararg is None
        or git_function.args.vararg.arg != "arguments"
        or git_function.args.kwarg is not None
        or git_function.args.kwonlyargs
        or git_function.args.defaults
        or git_function.args.posonlyargs
        or [argument.arg for argument in run_function.args.args]
        != ["root", "arguments", "timeout"]
        or run_function.args.vararg is not None
        or run_function.args.kwarg is not None
        or run_function.args.kwonlyargs
        or run_function.args.defaults
        or run_function.args.posonlyargs
    ):
        raise ContractError("Round 9 machine-report command signatures differ")

    subprocess_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr in {
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "getstatusoutput",
        }
    ]
    expected_subprocess_calls = sorted(
        (
            expression_dump(
                'subprocess.run(["git", "-C", str(root), *arguments], '
                "check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)"
            ),
            expression_dump(
                "subprocess.run(arguments, cwd=root, env=environment, "
                "stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)"
            ),
        )
    )
    if sorted(
        ast.dump(node, include_attributes=False) for node in subprocess_calls
    ) != expected_subprocess_calls:
        raise ContractError("Round 9 machine-report subprocess calls differ")

    if len(run_function.body) < 3:
        raise ContractError("Round 9 machine-report run_command body is incomplete")
    expected_environment_statements = (
        statement_dump("environment = dict(os.environ)"),
        statement_dump(
            'environment.update({"GOTOOLCHAIN": DEVELOPMENT_RUNTIME, '
            '"GOFLAGS": "-mod=readonly"})'
        ),
    )
    if tuple(
        ast.dump(statement, include_attributes=False)
        for statement in run_function.body[:2]
    ) != expected_environment_statements:
        raise ContractError("Round 9 machine-report subprocess environment differs")

    git_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "git_output"
    ]
    expected_git_calls = sorted(
        expression_dump(expression)
        for expression in (
            'git_output(root, "rev-parse", "HEAD")',
            'git_output(root, "rev-parse", "HEAD^{tree}")',
            'git_output(root, "status", "--porcelain=v1", "--untracked-files=all")',
            'git_output(root, "cat-file", "-t", tag_ref)',
            'git_output(root, "rev-parse", "--verify", tag_ref)',
            'git_output(root, "rev-parse", "--verify", f"{tag_ref}^{{commit}}")',
            'git_output(root, "rev-parse", "--verify", f"{tag_ref}^{{tree}}")',
        )
    )
    if sorted(ast.dump(node, include_attributes=False) for node in git_calls) != expected_git_calls:
        raise ContractError("Round 9 machine-report Git query allowlist differs")

    run_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_command"
    ]
    expected_run_calls = sorted(
        expression_dump(expression)
        for expression in (
            'run_command(root, [args.go, "run", "./cmd/round9-public-corpus-validator", "--root", "."], 900)',
            'run_command(root, [args.go, "run", "./cmd/round9-paired-malicious-corpus-runner", "--root", "."], 1800)',
            "run_command(root, command, 1800)",
        )
    )
    if sorted(ast.dump(node, include_attributes=False) for node in run_calls) != expected_run_calls:
        raise ContractError("Round 9 machine-report command allowlist differs")

    audit_function = functions["audit_report"]
    command_assignments = [
        node
        for node in audit_function.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "commands"
    ]
    expected_audit_commands = expression_dump(
        '[[args.go, "test", "-tags=sqlite_omit_load_extension", "./internal/audit", "-count=1"], '
        '[args.go, "test", "-tags=sqlite_omit_load_extension", "./internal/plugin", "-count=1"]]'
    )
    if (
        len(command_assignments) != 1
        or ast.dump(command_assignments[0].value, include_attributes=False)
        != expected_audit_commands
    ):
        raise ContractError("Round 9 machine-report audit/plugin command matrix differs")


def audit_python_source(
    text: str, source: Path, root: Path
) -> tuple[set[str], set[str]]:
    try:
        tree = ast.parse(text, filename=str(source))
    except SyntaxError as exc:
        raise ContractError(f"cannot parse reachable Python script {source}: {exc}") from exc
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    reviewed_execution_reference_ids = reviewed_round9_eval_execution_reference_ids(
        tree, source, root
    )
    primitive_reason = python_execution_primitive_reason(
        tree, aliases, reviewed_reference_ids=reviewed_execution_reference_ids
    )
    if primitive_reason:
        raise ContractError(f"{primitive_reason} in {source}")

    targets: set[str] = set()
    scripts = local_python_imports(tree, source, root)
    subprocess_calls = {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
    reviewed_dynamic_call_ids = reviewed_repository_secret_scan_dynamic_call_ids(
        tree, text, source, root
    ) | reviewed_round9_git_boundary_dynamic_call_ids(
        tree, source, root
    ) | reviewed_round9_eval_dynamic_call_ids(
        tree, source, root
    ) | reviewed_round9_host_evidence_dynamic_call_ids(
        tree, source, root
    ) | reviewed_round9_machine_report_test_dynamic_call_ids(
        tree, source, root
    ) | reviewed_round9_docker_sandbox_dynamic_call_ids(tree, source, root)
    forbidden_calls = {
        "eval",
        "exec",
        "compile",
        "runpy.run_module",
        "importlib.import_module",
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func, aliases)
        if not name:
            continue
        if name in forbidden_calls or name.startswith(("os.exec", "os.spawn")):
            raise ContractError(f"dynamic Python dispatch is forbidden in {source}: {name}")
        if name == "runpy.run_path":
            command = literal_command(node.args[0] if node.args else None)
            if not command or not command.endswith(".py"):
                raise ContractError(f"dynamic Python run_path is forbidden in {source}")
            scripts.add(command.removeprefix("./"))
            continue
        if name in {"os.system", "os.popen"}:
            raise ContractError(f"Python shell dispatch is forbidden in {source}: {name}")
        if name not in subprocess_calls:
            continue
        argument = node.args[0] if node.args else next(
            (keyword.value for keyword in node.keywords if keyword.arg in {"args", "cmd"}),
            None,
        )
        if id(node) in reviewed_dynamic_call_ids:
            continue
        command = literal_command(argument)
        if command is None:
            raise ContractError(f"dynamic Python command is forbidden in {source}: {name}")
        for keyword in node.keywords:
            if keyword.arg in {"cwd", "env"}:
                raise ContractError(
                    f"Python command with dynamic execution context is forbidden in {source}: {name}"
                )
            if keyword.arg == "shell" and not (
                isinstance(keyword.value, ast.Constant) and keyword.value.value is False
            ):
                raise ContractError(f"Python shell dispatch is forbidden in {source}: {name}")
        command_targets, command_scripts = audit_command_text(command, source)
        targets.update(command_targets)
        scripts.update(command_scripts)
    return targets, scripts


def validate_actionlint_config(text: str, source: Path) -> None:
    try:
        document = parse_workflow_yaml(text, source)
        root = require_yaml_keys(
            document, ("self-hosted-runner",), source, "actionlint"
        )
        self_hosted = require_yaml_keys(
            root["self-hosted-runner"],
            ("labels",),
            source,
            "actionlint.self-hosted-runner",
        )
        labels = yaml_sequence(
            self_hosted["labels"], source, "actionlint.self-hosted-runner.labels"
        )
        expected_labels: tuple[str, ...] = ()
        actual_labels = tuple(
            yaml_scalar(
                node,
                source,
                f"actionlint.self-hosted-runner.labels[{index}]",
            )
            for index, node in enumerate(labels)
        )
        if actual_labels != expected_labels:
            raise ContractError(
                "actionlint must not declare retired self-hosted runner labels"
            )
    except ContractError as exc:
        raise ContractError(f"actionlint configuration structure changed: {exc}") from exc
    if text != ACTIONLINT_CONFIG_TEXT:
        raise ContractError(
            f"actionlint configuration must match the exact reviewed text: {source}"
        )


def validate_workflow_layout(root: Path) -> None:
    root = root.resolve()
    workflow_dir = root / ".github/workflows"
    try:
        resolved_workflow_dir = workflow_dir.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ContractError(f"active workflow directory is missing: {workflow_dir}") from exc
    if workflow_dir.is_symlink() or not workflow_dir.is_dir():
        raise ContractError(
            f"active workflow directory must be a regular non-symlink directory: {workflow_dir}"
        )
    if resolved_workflow_dir != workflow_dir.absolute():
        raise ContractError(
            f"active workflow directory or one of its parents may not be a symlink: {workflow_dir}"
        )

    actual_paths: list[str] = []
    for entry in workflow_dir.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise ContractError(
                f"active workflow directory may contain only regular workflow files: {entry}"
            )
        actual_paths.append(entry.relative_to(root).as_posix())
    expected_directory_paths = ACTIVE_WORKFLOW_PATHS + WORKFLOW_DIRECTORY_AUXILIARY_PATHS
    if set(actual_paths) != set(expected_directory_paths) or len(actual_paths) != len(
        expected_directory_paths
    ):
        raise ContractError(
            "workflow directory must contain exactly the three reviewed entrypoints and its README: "
            + ", ".join(expected_directory_paths)
        )

    round9_gate_path = root / ROUND9_GATE_WORKFLOW_PATH
    validate_round9_gate_workflow(
        read_regular_text(round9_gate_path, root), round9_gate_path
    )
    safe_gate_test_path = root / ROUND6_SAFE_GATE_TEST_SCRIPT
    if safe_gate_test_path.exists() or safe_gate_test_path.is_symlink():
        safe_gate_test_text = read_regular_text(safe_gate_test_path, root)
        if (
            hashlib.sha256(safe_gate_test_text.encode("utf-8")).hexdigest()
            != ROUND6_SAFE_GATE_TEST_SHA256
        ):
            raise ContractError("Round6 safe-gate test suite differs from reviewed contract")

    archive_path = root / ARCHIVED_RC_WORKFLOW_PATH
    archive_text = read_regular_text(archive_path, root)
    validate_archived_rc_workflow(archive_text, archive_path)
    if archive_path.resolve().is_relative_to(resolved_workflow_dir):
        raise ContractError("archived RC workflow must remain outside the executable workflow directory")


def default_entrypoints(root: Path) -> list[Path]:
    root = root.resolve()
    validate_workflow_layout(root)
    return [root / relative for relative in ACTIVE_WORKFLOW_PATHS]


def audit(root: Path, entrypoints: list[Path]) -> tuple[set[str], set[str]]:
    root = root.resolve()
    if (root / ".git").exists():
        validate_round9_independent_git_boundary(root)
    if (root / CPA_COMPAT_SCRIPT).exists():
        validate_cpa_module_pins(root)
    if (root / ".github/workflows/candidate.yml").exists():
        validate_consumed_boundary_files(root)
    makefile_text = read_regular_text(root / "Makefile", root)
    dependencies, recipes, dynamic_dependencies = parse_makefile(makefile_text)
    validate_release_mode_contracts(root)

    direct_targets: set[str] = set()
    inspected_scripts: set[str] = set()
    script_queue: list[str] = []
    for entrypoint in entrypoints:
        text = read_regular_text(entrypoint, root)
        if entrypoint.suffix.lower() in {".yml", ".yaml"}:
            name = entrypoint.name.lower()
            if name == "candidate.yml":
                validate_candidate_workflow(text, entrypoint)
            elif name == "codeql.yml":
                validate_codeql_workflow(text, entrypoint)
            elif name == "attested-prerelease.yml":
                validate_blocked_prerelease_workflow(text, entrypoint)
            elif name == "release-rc.yml":
                validate_rc_release_workflow(text, entrypoint)
            elif name == "round8-host-validation.yml":
                validate_round8_host_workflow(text, entrypoint)
            elif name == "policy-gate.yml":
                validate_round9_gate_workflow(text, entrypoint)
            elif name == "round9-host-validation.yml":
                validate_round9_host_workflow(text, entrypoint)
            elif name == "round9-release-rc.yml":
                validate_round9_rc_workflow(text, entrypoint)
            elif name == "release.yml":
                validate_formal_release_workflow(text, entrypoint)
                continue
            elif name == "release-promote.yml":
                validate_release_promote_workflow(text, entrypoint)
                continue
            elif name == "ci.yml" and (root / CPA_COMPAT_SCRIPT).exists():
                validate_ci_workflow(text, entrypoint)
            else:
                validate_workflow_safety(text, entrypoint)
            command_text = "\n".join(yaml_run_blocks(text))
        else:
            command_text = text
        targets, scripts = audit_command_text(command_text, entrypoint)
        direct_targets.update(targets)
        script_queue.extend(scripts)

    reviewed_control_scripts = (
        REPRODUCIBILITY_WRAPPER_SCRIPT,
        FROZEN_EVALUATION_TREE_SCRIPT,
        ROUND9_INDEPENDENT_AUDIT_SCRIPT,
    )
    if (
        (root / ".github/workflows/ci.yml").resolve()
        in {path.resolve() for path in entrypoints}
        and all((root / relative).exists() for relative in reviewed_control_scripts)
    ):
        script_queue.extend(reviewed_control_scripts)

    visited: set[str] = set()
    target_queue = list(direct_targets)
    while script_queue or target_queue:
        if script_queue:
            relative = script_queue.pop().removeprefix("./")
            if relative in inspected_scripts:
                continue
            if relative == FROZEN_EVALUATION_TREE_SCRIPT:
                script_path = root / relative
                try:
                    resolved = script_path.resolve(strict=True)
                except FileNotFoundError as exc:
                    raise ContractError(
                        f"required gate input is missing: {script_path}"
                    ) from exc
                if (
                    script_path.is_symlink()
                    or not script_path.is_file()
                    or (resolved != root and root not in resolved.parents)
                ):
                    raise ContractError(
                        f"reviewed frozen evaluation verifier must be a regular repository file: {script_path}"
                    )
                script_text = script_path.read_text(encoding="utf-8")
                validate_frozen_evaluation_tree_script(script_text, script_path)
                inspected_scripts.add(relative)
                continue
            if relative == ROUND6_DOC_FIXTURE_WRAPPER_SCRIPT:
                script_path = root / relative
                script_text = read_regular_text(script_path, root)
                validate_round6_doc_fixture_wrapper_script(script_text, script_path, root)
                inspected_scripts.add(relative)
                inspected_scripts.update(ROUND6_DOC_FIXTURE_DEPENDENCY_SHA256)
                continue
            if relative == "scripts/release-doc-consistency.sh":
                script_path = root / relative
                script_text = read_regular_text(script_path, root)
                expected_hash = ROUND6_DOC_FIXTURE_DEPENDENCY_SHA256[relative]
                if hashlib.sha256(script_text.encode("utf-8")).hexdigest() != expected_hash:
                    raise ContractError(
                        "real release document gate changed outside the reviewed contract"
                    )
                inspected_scripts.add(relative)
                continue
            if relative == ROUND6_SAFE_GATE_TEST_SCRIPT:
                script_path = root / relative
                script_text = read_regular_text(script_path, root)
                if (
                    hashlib.sha256(script_text.encode("utf-8")).hexdigest()
                    == ROUND6_SAFE_GATE_TEST_SHA256
                ):
                    inspected_scripts.add(relative)
                    continue
            if relative == ROUND9_MACHINE_REPORT_SCRIPT:
                script_path = root / relative
                script_text = read_regular_text(script_path, root)
                validate_round9_machine_report_script(script_text, script_path)
                inspected_scripts.add(relative)
                continue
            if relative in ROUND9_INDEPENDENT_AUDIT_REVIEWED_SCRIPT_SHA256:
                script_path = root / relative
                script_text = read_regular_text(script_path, root)
                validate_round9_independent_audit_reviewed_script(
                    script_text, script_path
                )
                inspected_scripts.add(relative)
                continue
            if relative in ROUND9_EVAL_REVIEWED_SCRIPT_SHA256:
                inspected_scripts.update(validate_round9_eval_tool_bundle(root))
                continue
            if relative == ROUND9_EVAL_INSTALL_SCRIPT:
                script_path = root / relative
                script_text = read_regular_text(script_path, root)
                validate_round9_eval_install_script(script_text, script_path)
                inspected_scripts.add(relative)
                continue
            if relative == ROUND9_HOST_EVIDENCE_TEST_SCRIPT:
                script_path = root / relative
                script_text = read_regular_text(script_path, root)
                validate_round9_host_evidence_test_script(script_text, script_path)
                inspected_scripts.add(relative)
                continue
            if relative in ROUND8_HOST_REVIEWED_SCRIPT_SHA256:
                script_path = root / relative
                script_text = read_regular_text(script_path, root)
                expected_hash = ROUND8_HOST_REVIEWED_SCRIPT_SHA256[relative]
                if hashlib.sha256(script_text.encode("utf-8")).hexdigest() != expected_hash:
                    raise ContractError(
                        f"Round8 Host runner script differs from reviewed contract: {relative}"
                    )
                inspected_scripts.add(relative)
                continue
            assert_safe_repo_path(Path(relative), root)
            if (
                FORBIDDEN_SCRIPT_NAME.search(Path(relative).name)
                and relative != REPRODUCIBILITY_WRAPPER_SCRIPT
            ):
                raise ContractError(f"Round6 entrypoint reaches forbidden script: {relative}")
            inspected_scripts.add(relative)
            script_path = root / relative
            script_text = read_regular_text(script_path, root)
            suffix = script_path.suffix.lower()
            if relative == ROUND9_HOST_EVIDENCE_SCRIPT:
                validate_round9_host_evidence_script(script_text, script_path)
            if relative == ROUND9_MACHINE_REPORT_TEST_SCRIPT:
                validate_round9_machine_report_test_script(script_text, script_path)
            if relative == ROUND9_DOCKER_SANDBOX_SCRIPT:
                validate_round9_docker_sandbox_script(script_text, script_path)
            if suffix == ".sh":
                if script_path.name in CANDIDATE_SCRIPT_SHA256:
                    validate_candidate_script(script_text, script_path)
                if relative == REPRODUCIBILITY_WRAPPER_SCRIPT:
                    validate_reproducibility_wrapper_script(script_text, script_path)
                if relative == ROUND6_PRIVACY_FIXTURE_SCRIPT:
                    validate_round6_privacy_fixture_script(script_text, script_path)
                if relative == CPA_COMPAT_SCRIPT:
                    validate_cpa_compat_script(script_text, script_path)
                if relative == "scripts/go-safe-development-test.sh":
                    validate_round6_go_safe_development_script(script_text, script_path)
                if script_path.name == "round6-reproducibility-test.sh":
                    validate_round6_reproducibility_script(script_text, script_path)
                if script_path.name == "build-linux-amd64.sh":
                    validate_round6_linux_build_script(script_text, script_path)
                command_text = script_text
                if script_path.name in {
                    "round6-candidate-artifacts.sh",
                    "round6-rc-artifacts.sh",
                }:
                    command_text = command_text.replace(
                        "release_require_commands make ", "release_require_commands "
                    ).replace('make -C "$root" -j1', "make")
                    if script_path.name == "round6-rc-artifacts.sh":
                        command_text = command_text.replace(
                            'make -C "$clone" -j1', "make"
                        ).replace("\\\n", " ")
                elif script_path.name == "verify-external-release-attestation-test.sh":
                    command_text = command_text.replace('make -C "$root"', "make")
                elif script_path.name == "round6-reproducibility-test.sh":
                    command_text = command_text.replace(
                        ROUND6_REPRODUCIBILITY_FORMAL_PACKAGE_COMMAND, "", 1
                    )
                elif relative == SOURCE_RELEASE_EXCLUSION_CONTRACT_TEST_SCRIPT:
                    if (
                        hashlib.sha256(command_text.encode("utf-8")).hexdigest()
                        != SOURCE_RELEASE_EXCLUSION_CONTRACT_TEST_SHA256
                    ):
                        raise ContractError(
                            "source-release exclusion test differs from the reviewed contract"
                        )
                    command_text = command_text.replace(
                        SOURCE_RELEASE_SAFE_SCRIPT_PATH_FIXTURE_LINE,
                        "  fixture/package-tar-gz.sh \\",
                        1,
                    ).replace(
                        SOURCE_RELEASE_SAFE_SHELL_FIXTURE_LINE,
                        "  fixture/package-tar-gz.sh; do",
                        1,
                    )
                targets, scripts = audit_command_text(command_text, script_path)
            elif suffix == ".py":
                targets, scripts = audit_python_source(script_text, script_path, root)
            else:
                raise ContractError(f"unsupported reachable script type: {relative}")
            target_queue.extend(targets)
            script_queue.extend(scripts)
            continue

        target = target_queue.pop()
        if target in visited:
            continue
        visited.add(target)
        if target in FORBIDDEN_TARGETS or FORBIDDEN_TARGET_NAME.search(target):
            raise ContractError(f"Round6 entrypoint reaches forbidden Make target: {target}")
        if target not in dependencies:
            raise ContractError(f"Round6 entrypoint reaches unknown Make target: {target}")
        if target == "round6-benchmark":
            validate_round6_makefile_contract(makefile_text, root / "Makefile")
        if dynamic_dependencies.get(target):
            raise ContractError(
                f"Round6 entrypoint reaches Make target with dynamic dependencies: {target}"
            )
        target_queue.extend(dependencies[target])
        recipe = recipes.get(target, "")
        recipe_targets, recipe_scripts = audit_command_text(
            recipe, root / f"Makefile:{target}"
        )
        target_queue.extend(recipe_targets)
        script_queue.extend(recipe_scripts)

    ci_entrypoint = root / ".github/workflows/ci.yml"
    required_script_paths = {
        REPRODUCIBILITY_WRAPPER_SCRIPT,
        FROZEN_EVALUATION_TREE_SCRIPT,
        *ROUND9_INDEPENDENT_AUDIT_REVIEWED_SCRIPT_SHA256,
        *ROUND9_EVAL_REVIEWED_SCRIPT_SHA256,
        ROUND9_EVAL_INSTALL_SCRIPT,
        ROUND9_HOST_EVIDENCE_TEST_SCRIPT,
        ROUND9_HOST_EVIDENCE_SCRIPT,
        ROUND9_MACHINE_REPORT_TEST_SCRIPT,
        ROUND9_DOCKER_SANDBOX_SCRIPT,
    }
    if ci_entrypoint in {path.resolve() for path in entrypoints} and all(
        (root / relative).exists() for relative in required_script_paths
    ):
        missing = required_script_paths - inspected_scripts
        if missing:
            raise ContractError(
                "active CI script gates do not reach reviewed audit-safety scripts: "
                + ", ".join(sorted(missing))
            )

    return visited, inspected_scripts


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument(
        "--entrypoint",
        action="append",
        default=[],
        help="repository-relative workflow or script to audit; repeatable",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = args.root.resolve()
    try:
        validate_round9_malicious_text_producer_static_closure(root)
        entrypoints = (
            [root / item for item in args.entrypoint]
            if args.entrypoint
            else default_entrypoints(root)
        )
        targets, scripts = audit(root, entrypoints)
    except (ContractError, UnicodeError, OSError) as exc:
        print(f"Round6 safe gate contract: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "Round6 safe gate contract: PASS: "
        f"entrypoints={len(entrypoints)} make_targets={len(targets)} scripts={len(scripts)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
