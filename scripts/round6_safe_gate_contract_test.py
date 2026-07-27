#!/usr/bin/env python3

from __future__ import annotations

import _imp
import ast
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True

_CONTRACT_PATH = Path(__file__).with_name("round6_safe_gate_contract.py").resolve()
_CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "round6_safe_gate_contract", _CONTRACT_PATH
)
if _CONTRACT_SPEC is None or _CONTRACT_SPEC.loader is None:
    raise RuntimeError("cannot load the reviewed Safe Gate contract by exact path")
_CONTRACT_MODULE = importlib.util.module_from_spec(_CONTRACT_SPEC)
sys.modules[_CONTRACT_SPEC.name] = _CONTRACT_MODULE
_CONTRACT_SPEC.loader.exec_module(_CONTRACT_MODULE)

from round6_safe_gate_contract import (
    ACTIONLINT_CONFIG_PATH,
    ACTIVE_RC_WORKFLOW_PATH,
    ACTIVE_WORKFLOW_PATHS,
    ARCHIVED_RC_WORKFLOW_PATH,
    BLOCKED_PRERELEASE_MARKER,
    CPA_CURRENT_COMMIT,
    CPA_CURRENT_GO_MOD_SUM,
    CPA_CURRENT_MODULE_SUM,
    CPA_CURRENT_VERSION,
    CPA_ROUND8_COMMIT,
    CPA_ROUND8_VERSION,
    CONSUMED_BOUNDARY_LINES,
    EXTERNAL_ATTESTATION_SCRIPT_SHA256,
    FORMAL_OPERATION_SCRIPTS,
    FORBIDDEN_TARGETS,
    RC_SOURCE_ARCHIVE_BACKUP_BINARY_ARCHIVE_PATH_PATTERN,
    RC_SOURCE_ARCHIVE_TRANSIENT_GUARD_BLOCK,
    RC_SOURCE_ARCHIVE_TRANSIENT_PATH_PATTERN,
    RC_SOURCE_ARCHIVE_TEST_BINARY_PATH_PATTERN,
    RC_SOURCE_ARCHIVE_SAFE_TEST_SOURCE_PATTERN,
    ROUND8_HOST_REVIEWED_SCRIPT_SHA256,
    ROUND6_SPARSE_PATTERNS,
    ROUND9_EVAL_REVIEWED_SCRIPT_SHA256,
    ROUND9_EVAL_INSTALL_SCRIPT_SHA256,
    ROUND9_DOCKER_SANDBOX_SCRIPT_SHA256,
    ROUND9_DOCKER_SANDBOX_SUBPROCESS_CONTRACT,
    ROUND9_HOST_EVIDENCE_COMMAND_FUNCTION_CONTRACT,
    ROUND9_HOST_EVIDENCE_SCRIPT_SHA256,
    ROUND9_HOST_EVIDENCE_TEST_SCRIPT_SHA256,
    ROUND9_INDEPENDENT_AUDIT_REVIEWED_SCRIPT_SHA256,
    ROUND9_MACHINE_REPORT_TEST_SCRIPT_SHA256,
    ROUND9_MACHINE_REPORT_TEST_SUBPROCESS_CONTRACT,
    ROUND9_MALICIOUS_TEXT_PRODUCER_STATIC_CLOSURE_SHA256,
    ROUND9_EVAL_SUBPROCESS_FUNCTION_CONTRACT,
    WORKFLOW_DIRECTORY_AUXILIARY_PATHS,
    ContractError,
    assert_safe_repo_path,
    audit,
    audit_python_source,
    default_entrypoints,
    mutation_shell_commands,
    mutating_command_reason,
    read_only_gh_api_mutation_reason,
    reject_repository_yaml_shadow,
    round9_eval_subprocess_function_contract,
    round9_host_evidence_command_function_contract,
    shell_command_segments,
    validate_blocked_prerelease_workflow,
    validate_candidate_script,
    validate_candidate_workflow,
    validate_ci_workflow,
    validate_codeql_workflow,
    validate_cpa_compat_script,
    validate_cpa_module_pins,
    validate_consumed_boundary_files,
    validate_formal_release_workflow,
    validate_frozen_evaluation_tree_script,
    validate_release_build_metadata_script,
    validate_release_mode_contracts,
    validate_rc_reproducible_release_asset_contract,
    validate_rc_release_workflow,
    validate_archived_rc_workflow,
    validate_release_promote_workflow,
    validate_reproducibility_wrapper_script,
    validate_rc_source_archive_transient_guard,
    validate_round6_doc_fixture_wrapper_script,
    validate_round6_go_safe_development_script,
    validate_round6_linux_build_script,
    validate_round6_makefile_contract,
    validate_round6_privacy_fixture_script,
    validate_round6_reproducibility_script,
    validate_round8_host_workflow,
    validate_round9_gate_workflow,
    validate_round9_host_workflow,
    validate_round9_independent_git_boundary,
    validate_round9_independent_audit_reviewed_script,
    validate_round9_eval_install_script,
    validate_round9_docker_sandbox_script,
    validate_round9_host_evidence_test_script,
    validate_round9_host_evidence_script,
    validate_round9_machine_report_test_script,
    validate_round9_eval_tool_bundle,
    validate_round9_machine_report_script,
    validate_round9_malicious_text_producer_static_closure,
    validate_round9_rc_workflow,
    validate_workflow_layout,
)


CHECKOUT_SHA = "a" * 40


class Round6SafeGateContractTest(unittest.TestCase):
    def test_repository_local_pyyaml_shadow_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            shadow_names = (
                "yaml.py",
                "yaml.pyc",
                "yaml",
                *(f"yaml{suffix}" for suffix in _imp.extension_suffixes()),
            )
            for relative in shadow_names:
                candidate = scripts / relative
                if candidate.suffix:
                    candidate.write_text(
                        "raise AssertionError('shadow executed')\n", encoding="utf-8"
                    )
                else:
                    candidate.mkdir()
                with self.subTest(relative=relative):
                    with self.assertRaisesRegex(
                        RuntimeError, "repository-local PyYAML shadow is forbidden"
                    ):
                        reject_repository_yaml_shadow(root, [str(scripts)])
                if candidate.is_dir():
                    candidate.rmdir()
                else:
                    candidate.unlink()

    def test_isolated_python_does_not_import_repository_sitecustomize(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "sitecustomize-executed"
            (root / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            contract = Path(__file__).with_name("round6_safe_gate_contract.py").resolve()
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(contract), "--help"],
                cwd=root,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertFalse(marker.exists())

    def test_round9_malicious_text_producer_static_closure_is_hash_bound(self):
        root = Path(__file__).resolve().parent.parent
        validate_round9_malicious_text_producer_static_closure(root)
        for relative, expected_hash in (
            ROUND9_MALICIOUS_TEXT_PRODUCER_STATIC_CLOSURE_SHA256.items()
        ):
            with self.subTest(relative=relative):
                self.assertEqual(
                    hashlib.sha256((root / relative).read_bytes()).hexdigest(),
                    expected_hash,
                )

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture_root = Path(temporary.name)
        for relative in ROUND9_MALICIOUS_TEXT_PRODUCER_STATIC_CLOSURE_SHA256:
            target = fixture_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((root / relative).read_bytes())
        validate_round9_malicious_text_producer_static_closure(fixture_root)

        inventory = (
            fixture_root
            / "docs/reports/ROUND9_MALICIOUS_TEXT_PRODUCER_INVENTORY.json"
        )
        inventory.write_bytes(inventory.read_bytes() + b"\n")
        with self.assertRaisesRegex(
            ContractError, "malicious-text producer static-closure artifact"
        ):
            validate_round9_malicious_text_producer_static_closure(fixture_root)

    def test_round9_independent_audit_scripts_require_exact_reviewed_hashes(self):
        root = Path(__file__).resolve().parent.parent
        for relative, expected in ROUND9_INDEPENDENT_AUDIT_REVIEWED_SCRIPT_SHA256.items():
            with self.subTest(relative=relative):
                source = root / relative
                original = source.read_text(encoding="utf-8")
                self.assertEqual(
                    hashlib.sha256(original.encode("utf-8")).hexdigest(), expected
                )
                validate_round9_independent_audit_reviewed_script(original, source)
                with self.assertRaisesRegex(
                    ContractError, "independent-audit verifier differs"
                ):
                    validate_round9_independent_audit_reviewed_script(
                        original + "\n# unreviewed mutation\n", source
                    )

    def test_round9_machine_report_script_requires_exact_reviewed_hash(self):
        root = Path(__file__).resolve().parent.parent
        source = root / "scripts/round9_machine_reports.py"
        original = source.read_text(encoding="utf-8")
        validate_round9_machine_report_script(original, source)
        mutations = (
            (
                "subprocess API",
                "result = subprocess.run(\n            [\"git\",",
                "result = subprocess.Popen(\n            [\"git\",",
            ),
            (
                "Git program",
                '["git", "-C", str(root), *arguments],',
                '["python3", "-C", str(root), *arguments],',
            ),
            (
                "Git timeout",
                "            stderr=subprocess.PIPE,\n            timeout=30,",
                "            stderr=subprocess.PIPE,\n            timeout=31,",
            ),
            (
                "Git query",
                'git_output(root, "status", "--porcelain=v1", "--untracked-files=all")',
                'git_output(root, "diff", "--porcelain=v1", "--untracked-files=all")',
            ),
            (
                "command cwd",
                "        cwd=root,\n        env=environment,",
                "        cwd=root.parent,\n        env=environment,",
            ),
            (
                "command environment",
                '{"GOTOOLCHAIN": DEVELOPMENT_RUNTIME, "GOFLAGS": "-mod=readonly"}',
                '{"GOTOOLCHAIN": DEVELOPMENT_RUNTIME, "GOFLAGS": "-mod=mod"}',
            ),
            (
                "public runner",
                '"./cmd/round9-public-corpus-validator",',
                '"./cmd/unreviewed-runner",',
            ),
            (
                "audit command",
                '"./internal/plugin", "-count=1"],',
                '"./internal/classifier", "-count=1"],',
            ),
            (
                "second subprocess",
                "    result = subprocess.run(\n        arguments,",
                "    subprocess.run(['true'], check=False)\n    result = subprocess.run(\n        arguments,",
            ),
        )
        for label, before, after in mutations:
            with self.subTest(label=label):
                self.assertEqual(original.count(before), 1)
                mutation = original.replace(before, after, 1)
                reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.ROUND9_MACHINE_REPORT_SCRIPT_SHA256",
                    reviewed_hash,
                ):
                    with self.assertRaisesRegex(ContractError, "Round 9 machine-report"):
                        validate_round9_machine_report_script(mutation, source)

        subprocess_block = """    result = subprocess.run(
        arguments,
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
"""
        self.assertEqual(original.count(subprocess_block), 1)
        dead_call_mutation = original.replace(
            subprocess_block,
            "    if False:\n"
            + textwrap.indent(subprocess_block, "    ")
            + "    result = subprocess.CompletedProcess(arguments, 0, stdout=bytes(), stderr=bytes())\n",
            1,
        )
        with mock.patch(
            "round6_safe_gate_contract.ROUND9_MACHINE_REPORT_SCRIPT_SHA256",
            hashlib.sha256(dead_call_mutation.encode("utf-8")).hexdigest(),
        ):
            with self.assertRaisesRegex(ContractError, "command-owner control flow"):
                validate_round9_machine_report_script(dead_call_mutation, source)

        copied_source = root / "scripts/copied_round9_machine_reports.py"
        with self.assertRaisesRegex(ContractError, "outside the reviewed path"):
            validate_round9_machine_report_script(original, copied_source)

    def checkout_step(self, patterns: tuple[str, ...] = ROUND6_SPARSE_PATTERNS) -> str:
        sparse = "\n".join(f"            {pattern}" for pattern in patterns)
        return f"""      - uses: actions/checkout@{CHECKOUT_SHA}
        with:
          persist-credentials: false
          filter: blob:none
          sparse-checkout-cone-mode: false
          sparse-checkout: |
{sparse}
"""

    def gate_step(self, continue_on_error: bool = False) -> str:
        ignored = "        continue-on-error: true\n" if continue_on_error else ""
        return f"""      - name: Round6 safe gate
{ignored}        run: |
          python3 -B scripts/round6_safe_gate_contract_test.py
          python3 -B scripts/round6_safe_gate_contract.py --root .
          ./scripts/release-doc-consistency.sh
"""

    def run_step(self, command: str) -> str:
        if "\n" not in command:
            return f"      - run: {command}\n"
        body = "\n".join(f"          {line}" for line in command.splitlines())
        return f"      - run: |\n{body}\n"

    def workflow(
        self,
        command: str,
        *,
        patterns: tuple[str, ...] = ROUND6_SPARSE_PATTERNS,
        gate: str = "immediate",
        continue_on_error: bool = False,
    ) -> str:
        checkout = self.checkout_step(patterns)
        safe_gate = self.gate_step(continue_on_error)
        command_step = self.run_step(command)
        if gate == "immediate":
            steps = checkout + safe_gate + command_step
        elif gate == "late":
            steps = checkout + command_step + safe_gate
        elif gate == "missing":
            steps = checkout + command_step
        else:
            raise AssertionError(gate)
        return f"""name: CI

on:
  push:

jobs:
  quality:
    runs-on: ubuntu-24.04
    steps:
{steps}"""

    def fixture(
        self,
        makefile: str,
        command: str = "make safe",
        scripts: dict[str, str] | None = None,
        workflow: str | None = None,
    ) -> tuple[Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / ".github/workflows").mkdir(parents=True)
        (root / "scripts").mkdir()
        (root / "Makefile").write_text(makefile, encoding="utf-8")
        entrypoint = root / ".github/workflows/ci.yml"
        entrypoint.write_text(workflow or self.workflow(command), encoding="utf-8")
        payloads = {
            "scripts/round6_safe_gate_contract.py": "# synthetic gate\n",
            "scripts/round6_safe_gate_contract_test.py": "# synthetic gate tests\n",
            "scripts/release-doc-consistency.sh": Path(__file__).with_name(
                "release-doc-consistency.sh"
            ).read_text(encoding="utf-8"),
        }
        payloads.update(scripts or {})
        for relative, content in payloads.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return root, entrypoint

    def test_safe_transitive_graph_passes(self):
        root, entrypoint = self.fixture(
            "unit-test: test\n\ntest:\n\t@true\n",
            "make unit-test",
        )
        targets, _ = audit(root, [entrypoint])
        self.assertEqual(targets, {"unit-test", "test"})

    def test_all_legacy_targets_fail(self):
        for target in sorted(FORBIDDEN_TARGETS):
            with self.subTest(target=target):
                root, entrypoint = self.fixture(f"{target}:\n\t@true\n", f"make {target}")
                with self.assertRaisesRegex(ContractError, "forbidden Make target"):
                    audit(root, [entrypoint])

    def test_second_make_on_same_line_is_audited(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\nholdout-test:\n\t@true\n",
            "make safe && make holdout-test",
        )
        with self.assertRaisesRegex(ContractError, "forbidden Make target"):
            audit(root, [entrypoint])

    def test_unknown_target_fails_closed(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "make unreviewed-target")
        with self.assertRaisesRegex(ContractError, "unknown Make target"):
            audit(root, [entrypoint])

    def test_dynamic_make_target_fails_closed(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "make ${ROUND6_TARGET}")
        with self.assertRaisesRegex(ContractError, "dynamic Make target"):
            audit(root, [entrypoint])

    def test_make_directory_dispatch_fails_closed(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "make -C alternate safe")
        with self.assertRaisesRegex(ContractError, "Make directory/file/eval dispatch"):
            audit(root, [entrypoint])

    def test_shell_c_dispatch_fails_closed(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "bash -c 'make safe'")
        with self.assertRaisesRegex(ContractError, "dynamic shell dispatch"):
            audit(root, [entrypoint])

    def test_python_c_dispatch_fails_closed(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "python3 -c 'print(1)'")
        with self.assertRaisesRegex(ContractError, "dynamic Python dispatch"):
            audit(root, [entrypoint])

    def test_go_all_packages_in_workflow_fails(self):
        root, entrypoint = self.fixture("safe:\n\t@true\n", "go test ./...")
        with self.assertRaisesRegex(ContractError, "reachable go"):
            audit(root, [entrypoint])

    def test_go_all_packages_in_make_recipe_fails(self):
        root, entrypoint = self.fixture("safe:\n\tgo test ./...\n")
        with self.assertRaisesRegex(ContractError, "reachable go"):
            audit(root, [entrypoint])

    def test_go_all_packages_in_shell_script_fails(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "bash scripts/driver.sh",
            {"scripts/driver.sh": "#!/usr/bin/env bash\ngo test ./...\n"},
        )
        with self.assertRaisesRegex(ContractError, "reachable go"):
            audit(root, [entrypoint])

    def test_python_static_subprocess_is_recursively_audited(self):
        root, entrypoint = self.fixture(
            "holdout-test:\n\t@true\n",
            "python3 scripts/driver.py",
            {
                "scripts/driver.py": (
                    "import subprocess\n"
                    "subprocess.run(['make', 'holdout-test'], check=True)\n"
                )
            },
        )
        with self.assertRaisesRegex(ContractError, "forbidden Make target"):
            audit(root, [entrypoint])

    def test_direct_repository_executable_in_workflow_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "./tools/run-gate",
            {"tools/run-gate": "#!/usr/bin/env bash\nexit 0\n"},
        )
        with self.assertRaisesRegex(ContractError, "direct repository executable"):
            audit(root, [entrypoint])

    def test_direct_repository_executable_in_make_recipe_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t./tools/run-gate\n",
            scripts={"tools/run-gate": "#!/usr/bin/env bash\nexit 0\n"},
        )
        with self.assertRaisesRegex(ContractError, "direct repository executable"):
            audit(root, [entrypoint])

    def test_direct_repository_executable_in_python_subprocess_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "python3 scripts/driver.py",
            {
                "scripts/driver.py": (
                    "import subprocess\n"
                    "subprocess.run(['./tools/run-gate'], check=True)\n"
                ),
                "tools/run-gate": "#!/usr/bin/env bash\nexit 0\n",
            },
        )
        with self.assertRaisesRegex(ContractError, "direct repository executable"):
            audit(root, [entrypoint])

    def test_shell_array_execution_substitutions_fail_closed(self):
        commands = (
            'values=("$(./tools/run-gate)")\nmake safe',
            'values=(\n  "$(./tools/run-gate)"\n)\nmake safe',
            'values=(`./tools/run-gate`)\nmake safe',
            'values=( <(./tools/run-gate) )\nmake safe',
        )
        for command in commands:
            with self.subTest(command=command):
                root, entrypoint = self.fixture("safe:\n\t@true\n", command)
                with self.assertRaisesRegex(
                    ContractError, "shell array contains executable substitution"
                ):
                    audit(root, [entrypoint])

    def test_shell_array_single_quoted_substitution_is_literal(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "values=('$(literal)' '<(literal)' '>(literal)' '`literal`')\nmake safe",
        )
        targets, _ = audit(root, [entrypoint])
        self.assertEqual(targets, {"safe"})

    def test_even_trailing_backslashes_do_not_hide_next_command(self):
        command = "printf '%s' safe " + "\\\\" + "\n$runner\nmake safe"
        root, entrypoint = self.fixture("safe:\n\t@true\n", command)
        with self.assertRaisesRegex(ContractError, "dynamic command variable"):
            audit(root, [entrypoint])

    def test_read_only_gh_api_parser_handles_shell_tokens_and_command_boundaries(self):
        rejected = (
            'gh api --method "PATCH" repos/o/r/releases/1',
            "gh api -X 'post' repos/o/r/releases",
            'gh api "-f" draft=false repos/o/r/releases/1',
            "gh api '--field' draft=false repos/o/r/releases/1",
            '"/usr/bin/gh" api --input request.json repos/o/r/releases/1',
            r"g\h api -F draft=false repos/o/r/releases/1",
            "command /usr/bin/gh api -fdraft=false repos/o/r/releases/1",
            "env GH_TOKEN=fixture /usr/bin/gh api --raw-field=draft=false repos/o/r/releases/1",
            'method=PATCH; gh api --method "$method" repos/o/r/releases/1',
            'gh api --method\\\n=DELETE repos/o/r/releases/1',
            'gh a\\\npi --method PUT repos/o/r/releases/1',
            'gh api --fi\\\neld draft=false repos/o/r/releases/1',
            'api_write() { gh api "$@"; }; api_write -f draft=false repos/o/r/releases/1',
            'api_write () { gh api "$@"; }; api_write -f draft=false repos/o/r/releases/1',
            "alias api_write='command gh api'; api_write -F draft=false repos/o/r/releases/1",
            'gh api --method GET -H "X-HTTP-Method-Override: POST" repos/o/r/releases/1',
        )
        for command in rejected:
            with self.subTest(rejected=command):
                self.assertIsNotNone(read_only_gh_api_mutation_reason(command))

        allowed = (
            "gh api repos/o/r/releases | jq -f filter.jq",
            "# gh api -f draft=false repos/o/r/releases/1",
            "printf '%s\\n' 'gh api --input request.json'",
            "gh api --method GET -f page=2 repos/o/r/releases",
            "gh api -F page=2 --method=GET repos/o/r/releases",
            'command "/usr/bin/gh" api --method "GET" --field page=2 repos/o/r/releases',
            "GH API -F draft=false repos/o/r/releases/1",
            "gh api -- --field=draft=false",
        )
        for command in allowed:
            with self.subTest(allowed=command):
                self.assertIsNone(read_only_gh_api_mutation_reason(command))

    def test_python_dynamic_subprocess_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "python3 scripts/driver.py",
            {
                "scripts/driver.py": (
                    "import subprocess\n"
                    "command = ['make', 'safe']\n"
                    "subprocess.run(command, check=True)\n"
                )
            },
        )
        with self.assertRaisesRegex(ContractError, "dynamic Python command"):
            audit(root, [entrypoint])

    def test_python_shell_true_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "python3 scripts/driver.py",
            {
                "scripts/driver.py": (
                    "import subprocess\n"
                    "subprocess.run(['make', 'safe'], shell=True, check=True)\n"
                )
            },
        )
        with self.assertRaisesRegex(ContractError, "Python shell dispatch"):
            audit(root, [entrypoint])

    def test_python_os_system_fails_closed(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "python3 scripts/driver.py",
            {"scripts/driver.py": "import os\nos.system('make safe')\n"},
        )
        with self.assertRaisesRegex(
            ContractError, "execution primitive|Python shell dispatch"
        ):
            audit(root, [entrypoint])

    def test_python_local_import_is_recursively_audited(self):
        root, entrypoint = self.fixture(
            "holdout-test:\n\t@true\n",
            "python3 scripts/driver.py",
            {
                "scripts/driver.py": "import helper\n",
                "scripts/helper.py": (
                    "import subprocess\n"
                    "subprocess.run(['make', 'holdout-test'], check=True)\n"
                ),
            },
        )
        with self.assertRaisesRegex(ContractError, "forbidden Make target"):
            audit(root, [entrypoint])

    def test_restricted_script_name_is_refused_before_read(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            "python3 scripts/private_helper.py",
            {"scripts/private_helper.py": "raise AssertionError('must not be parsed')\n"},
        )
        with self.assertRaisesRegex(ContractError, "refuses restricted path before reading"):
            audit(root, [entrypoint])

    def test_only_exact_reviewed_evaluation_contract_sources_are_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            allowed = (
                "scripts/round9_external_evaluation_contract.py",
                "scripts/round9_external_evaluation_contract_test.py",
            )
            for relative in allowed:
                with self.subTest(allowed=relative):
                    self.assertEqual(
                        assert_safe_repo_path(Path(relative), root),
                        root / relative,
                    )
            for relative in (
                "scripts/round9_external_evaluation_contract_private.py",
                "other/round9_external_evaluation_contract.py",
                "scripts/private_helper.py",
            ):
                with self.subTest(rejected=relative):
                    with self.assertRaisesRegex(
                        ContractError, "refuses restricted path before reading"
                    ):
                        assert_safe_repo_path(Path(relative), root)

    def test_checkout_without_gate_fails(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            workflow=self.workflow("make safe", gate="missing"),
        )
        with self.assertRaisesRegex(ContractError, "immediately after checkout"):
            audit(root, [entrypoint])

    def test_gate_after_repository_command_fails(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            workflow=self.workflow("make safe", gate="late"),
        )
        with self.assertRaisesRegex(ContractError, "immediately after checkout"):
            audit(root, [entrypoint])

    def test_gate_continue_on_error_fails(self):
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            workflow=self.workflow("make safe", continue_on_error=True),
        )
        with self.assertRaisesRegex(ContractError, "immediately after checkout"):
            audit(root, [entrypoint])

    def test_sparse_checkout_missing_private_pattern_fails(self):
        patterns = tuple(
            pattern
            for pattern in ROUND6_SPARSE_PATTERNS
            if pattern != "!/cmd/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*"
        )
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            workflow=self.workflow("make safe", patterns=patterns),
        )
        with self.assertRaisesRegex(ContractError, "sparse checkout differs"):
            audit(root, [entrypoint])

    def test_sparse_checkout_missing_consumed_pattern_fails(self):
        self.assertIn("!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*", ROUND6_SPARSE_PATTERNS)
        patterns = tuple(
            pattern
            for pattern in ROUND6_SPARSE_PATTERNS
            if pattern != "!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*"
        )
        root, entrypoint = self.fixture(
            "safe:\n\t@true\n",
            workflow=self.workflow("make safe", patterns=patterns),
        )
        with self.assertRaisesRegex(ContractError, "sparse checkout differs"):
            audit(root, [entrypoint])

    def test_windows_or_macos_runner_fails(self):
        for runner in ("windows-2025", "macos-15"):
            with self.subTest(runner=runner):
                root, entrypoint = self.fixture(
                    "safe:\n\t@true\n",
                    workflow=self.workflow("make safe").replace(
                        "runs-on: ubuntu-24.04", f"runs-on: {runner}"
                    ),
                )
                with self.assertRaisesRegex(ContractError, "Linux amd64 runner"):
                    audit(root, [entrypoint])

    def test_workflow_defaults_shell_override_fails(self):
        workflow = self.workflow("make safe").replace(
            "jobs:\n",
            "defaults:\n  run:\n    shell: bash {0}\n\njobs:\n",
        )
        root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
        with self.assertRaisesRegex(ContractError, "override the reviewed run shell"):
            audit(root, [entrypoint])

    def test_workflow_container_override_fails(self):
        workflow = self.workflow("make safe").replace(
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-24.04\n    container: attacker-controlled:latest\n",
            1,
        )
        root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
        with self.assertRaisesRegex(ContractError, "may not define container"):
            audit(root, [entrypoint])

    def test_workflow_quoted_or_anchored_execution_keys_fail(self):
        mutations = (
            self.workflow("make safe").replace(
                "jobs:\n", '"defaults":\n  run:\n    shell: bash {0}\n\njobs:\n'
            ),
            self.workflow("make safe").replace(
                "jobs:\n", "defaults: &unsafe_defaults\n  run:\n    shell: bash {0}\n\njobs:\n"
            ),
            self.workflow("make safe").replace(
                "    runs-on: ubuntu-24.04\n",
                '    runs-on: ubuntu-24.04\n    "container": attacker-controlled:latest\n',
                1,
            ),
            self.workflow("make safe").replace(
                "        run: |\n",
                '        "shell": bash {0}\n        run: |\n',
                1,
            ),
            self.workflow("make safe").replace(
                "jobs:\n", "&unsafe_key defaults:\n  run:\n    shell: bash {0}\n\njobs:\n"
            ),
            self.workflow("make safe").replace(
                "jobs:\n", "!!str defaults:\n  run:\n    shell: bash {0}\n\njobs:\n"
            ),
            self.workflow("make safe").replace(
                "    runs-on: ubuntu-24.04\n",
                "    runs-on: ubuntu-24.04\n    &unsafe_key container: attacker-controlled:latest\n",
                1,
            ),
            self.workflow("make safe").replace(
                "        run: |\n",
                "        &unsafe_key shell: bash {0}\n        run: |\n",
                1,
            ),
            self.workflow("make safe").replace(
                "jobs:\n",
                "&env_key env:\n  &unsafe_key BASH_ENV: ./scripts/evil-bash-env.sh\n\njobs:\n",
            ),
            self.workflow("make safe").replace(
                "jobs:\n", "defaults: *unsafe_defaults\n\njobs:\n"
            ),
            "%YAML 1.2\n---\n" + self.workflow("make safe"),
            self.workflow("make safe").replace(
                "jobs:\n", "env: {BASH_ENV: ./scripts/evil-bash-env.sh}\n\njobs:\n"
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(index=index):
                root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
                with self.assertRaisesRegex(
                    ContractError, "quoted|anchors|override the reviewed run shell"
                ):
                    audit(root, [entrypoint])

    def test_workflow_dangerous_execution_environment_fails(self):
        workflow = self.workflow("make safe").replace(
            "jobs:\n", "env:\n  BASH_ENV: ./scripts/evil-bash-env.sh\n\njobs:\n"
        )
        root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
        with self.assertRaisesRegex(ContractError, "top-level env|dangerous execution-context"):
            audit(root, [entrypoint])

    def test_workflow_spaced_semantic_execution_keys_fail(self):
        mutations = (
            self.workflow("make safe").replace(
                "jobs:\n", "defaults :\n  run:\n    shell: bash {0}\n\njobs:\n"
            ),
            self.workflow("make safe").replace(
                "    runs-on: ubuntu-24.04\n",
                "    runs-on: ubuntu-24.04\n    container : attacker-controlled:latest\n",
                1,
            ),
            self.workflow("make safe").replace(
                "        run: |\n", "        shell : bash {0}\n        run: |\n", 1
            ),
            self.workflow("make safe").replace(
                "jobs:\n", "env :\n  BASH_ENV : ./scripts/evil-bash-env.sh\n\njobs:\n"
            ),
            self.workflow("make safe").replace(
                "      - name: Round6 safe gate\n",
                "      - name: Round6 safe gate\n        continue-on-error : true\n",
                1,
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(index=index):
                root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
                with self.assertRaisesRegex(
                    ContractError,
                    "override the reviewed run shell|container|step shell|top-level env|immediately after checkout",
                ):
                    audit(root, [entrypoint])

    def test_workflow_explicit_mapping_key_fails(self):
        workflow = self.workflow("make safe").replace(
            "jobs:\n", "? defaults\n:\n  run:\n    shell: bash {0}\n\njobs:\n"
        )
        root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
        with self.assertRaisesRegex(ContractError, "explicit YAML mapping keys"):
            audit(root, [entrypoint])

    def test_workflow_duplicate_semantic_key_fails(self):
        workflow = self.workflow("make safe").replace(
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-24.04\n    runs-on : ubuntu-24.04\n",
            1,
        )
        root, entrypoint = self.fixture("safe:\n\t@true\n", workflow=workflow)
        with self.assertRaisesRegex(ContractError, "duplicate semantic key"):
            audit(root, [entrypoint])

    def reproducibility_script(self) -> tuple[str, Path]:
        source = Path(__file__).with_name("round6-reproducibility-test.sh")
        return source.read_text(encoding="utf-8"), source

    def test_reproducibility_sparse_contract_passes(self):
        text, source = self.reproducibility_script()
        validate_round6_reproducibility_script(text, source)

    def test_reproducibility_sparse_contract_mismatch_fails(self):
        original, source = self.reproducibility_script()
        text = original.replace(" '!/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'", "", 1)
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "differs from the workflow contract"):
            validate_round6_reproducibility_script(text, source)

    def test_reproducibility_consumed_sparse_contract_mismatch_fails(self):
        original, source = self.reproducibility_script()
        text = original.replace(" '!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'", "", 1)
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "differs from the workflow contract"):
            validate_round6_reproducibility_script(text, source)

    def test_reproducibility_entry_mode_contract_is_locked(self):
        original, source = self.reproducibility_script()
        text = original.replace(
            'reproducibility_mode="${ROUND6_REPRODUCIBILITY_MODE:-release}"',
            'reproducibility_mode="${ROUND6_REPRODUCIBILITY_MODE:-development}"',
            1,
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "entry mode"):
            validate_round6_reproducibility_script(text, source)

    def test_consumed_nonworkflow_boundaries_are_mutation_locked(self):
        root = Path(__file__).parent.parent
        validate_consumed_boundary_files(root)
        for relative, required_lines in CONSUMED_BOUNDARY_LINES.items():
            for required in required_lines:
                with self.subTest(relative=relative, required=required):
                    temporary = tempfile.TemporaryDirectory()
                    self.addCleanup(temporary.cleanup)
                    fixture = Path(temporary.name)
                    for boundary_relative in CONSUMED_BOUNDARY_LINES:
                        source = root / boundary_relative
                        destination = fixture / boundary_relative
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        text = source.read_text(encoding="utf-8")
                        if boundary_relative == relative:
                            text = text.replace(required + "\n", "", 1)
                        destination.write_text(text, encoding="utf-8")
                    with self.assertRaisesRegex(ContractError, "consumed exclusion boundary"):
                        validate_consumed_boundary_files(fixture)

    def test_round9_independent_git_boundary_rejects_force_added_plaintext(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)
        (root / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
        validate_round9_independent_git_boundary(root)

        restricted = root / "testdata/round9-independent-benign-v1/cases.jsonl"
        restricted.parent.mkdir(parents=True)
        restricted.write_text('{"synthetic":true}\n', encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(root), "add", "--force", str(restricted.relative_to(root))],
            check=True,
        )
        with self.assertRaisesRegex(ContractError, "tracked in Git history"):
            validate_round9_independent_git_boundary(root)

    def test_round9_independent_git_boundary_normalizes_timeout(self):
        with mock.patch(
            "round6_safe_gate_contract.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["git", "ls-files"], timeout=30),
        ):
            with self.assertRaisesRegex(
                ContractError, "cannot verify the Round 9 independent Git boundary"
            ):
                validate_round9_independent_git_boundary(Path("/synthetic/repository"))

    def test_round9_independent_git_boundary_dynamic_call_is_narrowly_reviewed(self):
        root = Path(__file__).resolve().parent.parent
        source = root / "scripts/round6_safe_gate_contract.py"
        original = source.read_text(encoding="utf-8")
        audit_python_source(original, source, root)

        mutations = (
            (
                "program",
                'command = [\n        "git",\n        "-C",',
                'command = [\n        "python3",\n        "-C",',
            ),
            (
                "repository argument",
                '        "-C",\n        str(root),\n        "ls-files",',
                '        "--git-dir",\n        str(root),\n        "ls-files",',
            ),
            (
                "root conversion",
                '        str(root),\n        "ls-files",',
                '        str(root / "nested"),\n        "ls-files",',
            ),
            (
                "pathspec",
                '        "--",\n        ROUND9_INDEPENDENT_GIT_PATHSPEC,\n    ]\n    try:\n        completed =',
                '        "--",\n        "README.md",\n    ]\n    try:\n        completed =',
            ),
            (
                "stdin",
                "            stdin=subprocess.DEVNULL,\n            capture_output=True,",
                "            stdin=subprocess.PIPE,\n            capture_output=True,",
            ),
            (
                "capture output",
                "            capture_output=True,\n            check=False,",
                "            capture_output=False,\n            check=False,",
            ),
            (
                "check",
                "            check=False,\n            timeout=30,",
                "            check=True,\n            timeout=30,",
            ),
            (
                "timeout",
                "            check=False,\n            timeout=30,\n        )\n    except subprocess.TimeoutExpired as exc:",
                "            check=False,\n            timeout=31,\n        )\n    except subprocess.TimeoutExpired as exc:",
            ),
            (
                "shell",
                "            check=False,\n            timeout=30,\n        )\n    except subprocess.TimeoutExpired as exc:",
                "            check=False,\n            timeout=30,\n            shell=False,\n        )\n    except subprocess.TimeoutExpired as exc:",
            ),
            (
                "cwd",
                "            check=False,\n            timeout=30,\n        )\n    except subprocess.TimeoutExpired as exc:",
                "            check=False,\n            timeout=30,\n            cwd=root,\n        )\n    except subprocess.TimeoutExpired as exc:",
            ),
            (
                "env",
                "            check=False,\n            timeout=30,\n        )\n    except subprocess.TimeoutExpired as exc:",
                "            check=False,\n            timeout=30,\n            env={},\n        )\n    except subprocess.TimeoutExpired as exc:",
            ),
            (
                "keyword command",
                "        completed = subprocess.run(\n            command,\n            stdin=",
                "        completed = subprocess.run(\n            args=command,\n            stdin=",
            ),
            (
                "second dynamic call",
                "        )\n    except subprocess.TimeoutExpired as exc:",
                "        )\n        subprocess.run(command, check=False)\n    except subprocess.TimeoutExpired as exc:",
            ),
            (
                "extra try body statement",
                "    try:\n        completed = subprocess.run(",
                "    try:\n        pass\n        completed = subprocess.run(",
            ),
            (
                "handler type",
                "    except subprocess.TimeoutExpired as exc:",
                "    except OSError as exc:",
            ),
            (
                "handler alias",
                "    except subprocess.TimeoutExpired as exc:",
                "    except subprocess.TimeoutExpired as error:",
            ),
            (
                "handler statement",
                "    except subprocess.TimeoutExpired as exc:\n        raise ContractError(",
                "    except subprocess.TimeoutExpired as exc:\n        pass\n        raise ContractError(",
            ),
            (
                "handler exception class",
                "        raise ContractError(\n            \"cannot verify the Round 9 independent Git boundary\"",
                "        raise RuntimeError(\n            \"cannot verify the Round 9 independent Git boundary\"",
            ),
            (
                "handler cause",
                "        ) from exc\n    if completed.returncode",
                "        ) from None\n    if completed.returncode",
            ),
            (
                "try else",
                "        ) from exc\n    if completed.returncode",
                "        ) from exc\n    else:\n        pass\n    if completed.returncode",
            ),
            (
                "try finally",
                "        ) from exc\n    if completed.returncode",
                "        ) from exc\n    finally:\n        pass\n    if completed.returncode",
            ),
            (
                "second handler",
                "        ) from exc\n    if completed.returncode",
                "        ) from exc\n    except OSError:\n        pass\n    if completed.returncode",
            ),
            (
                "second try",
                "        ) from exc\n    if completed.returncode",
                "        ) from exc\n    try:\n        pass\n    except OSError:\n        pass\n    if completed.returncode",
            ),
        )
        for label, before, after in mutations:
            with self.subTest(label=label):
                self.assertEqual(original.count(before), 1)
                mutation = original.replace(before, after, 1)
                with self.assertRaisesRegex(
                    ContractError,
                    "reviewed Round 9 Git boundary subprocess contract|dynamic Python command",
                ):
                    audit_python_source(mutation, source, root)

        try_block = """    try:
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
"""
        direct_call_block = """    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )
"""
        self.assertEqual(original.count(try_block), 1)
        no_try_mutation = original.replace(
            try_block,
            direct_call_block,
            1,
        )
        with self.assertRaisesRegex(
            ContractError,
            "reviewed Round 9 Git boundary subprocess contract|dynamic Python command",
        ):
            audit_python_source(no_try_mutation, source, root)

        copied_source = root / "scripts/copied_safe_gate.py"
        with self.assertRaisesRegex(ContractError, "dynamic Python command"):
            audit_python_source(original, copied_source, root)

    def test_round9_eval_tool_bundle_is_exact_and_command_scoped(self):
        repository = Path(__file__).resolve().parent.parent
        self.assertEqual(
            validate_round9_eval_tool_bundle(repository),
            set(ROUND9_EVAL_REVIEWED_SCRIPT_SHA256),
        )
        self.assertEqual(
            set(ROUND9_EVAL_REVIEWED_SCRIPT_SHA256),
            set(ROUND9_EVAL_SUBPROCESS_FUNCTION_CONTRACT),
        )

        def fixture() -> Path:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name)
            for relative in ROUND9_EVAL_REVIEWED_SCRIPT_SHA256:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((repository / relative).read_bytes())
            return root

        byte_mutation_root = fixture()
        byte_mutation_path = (
            byte_mutation_root / "tools/round9-eval/round9_eval_core.py"
        )
        byte_mutation_path.write_text(
            byte_mutation_path.read_text(encoding="utf-8") + "\n# byte drift\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ContractError, "reviewed SHA-256"):
            validate_round9_eval_tool_bundle(byte_mutation_root)

        command_mutation_root = fixture()
        command_relative = "tools/round9-eval/round9_eval_core.py"
        command_mutation_path = command_mutation_root / command_relative
        command_original = command_mutation_path.read_text(encoding="utf-8")
        before = '            "pkeyutl",\n            "-sign",'
        after = '            "pkey",\n            "-sign",'
        self.assertEqual(command_original.count(before), 1)
        command_mutation = command_original.replace(before, after, 1)
        command_mutation_path.write_text(command_mutation, encoding="utf-8")
        command_hash = hashlib.sha256(command_mutation.encode("utf-8")).hexdigest()
        with mock.patch.dict(
            ROUND9_EVAL_REVIEWED_SCRIPT_SHA256,
            {command_relative: command_hash},
        ), mock.patch.dict(
            ROUND9_EVAL_SUBPROCESS_FUNCTION_CONTRACT,
            {
                command_relative: round9_eval_subprocess_function_contract(
                    command_mutation, command_mutation_path
                )
            },
        ):
            with self.assertRaisesRegex(ContractError, "OpenSSL|argv"):
                validate_round9_eval_tool_bundle(command_mutation_root)

        primitive_mutations = (
            (
                "os.system",
                "\n\ndef injected_exec() -> int:\n    return os.system('true')\n",
                "execution primitive",
            ),
            (
                "getattr os.system",
                "\n\ndef injected_getattr() -> object:\n    return getattr(os, 'system')('true')\n",
                "getattr",
            ),
            (
                "asyncio subprocess",
                "\nimport asyncio\n\nasync def injected_asyncio() -> object:\n"
                "    return await asyncio.create_subprocess_exec('true')\n",
                "execution primitive",
            ),
            (
                "execution module alias",
                "\nimport os as operating_system\n\ndef injected_alias() -> int:\n"
                "    return operating_system.system('true')\n",
                "execution primitive",
            ),
            (
                "module object alias os",
                "\n\ndef injected_module_alias() -> int:\n    module = os\n"
                "    return module.system('true')\n",
                "module object",
            ),
            (
                "module object alias subprocess",
                "\n\ndef injected_subprocess_alias() -> object:\n    module = subprocess\n"
                "    return module.run(['true'], check=False)\n",
                "module object",
            ),
            (
                "globals module lookup",
                "\n\ndef injected_globals() -> int:\n"
                "    return globals()['os'].system('true')\n",
                "namespace lookup|execution primitive",
            ),
            (
                "builtins exec",
                "\nimport builtins\n\ndef injected_builtins() -> None:\n"
                "    builtins.exec(\"raise SystemExit(1)\")\n",
                "execution primitive",
            ),
            (
                "builtins import",
                "\nimport builtins\n\ndef injected_import() -> object:\n"
                "    return builtins.__import__('os').system('true')\n",
                "execution primitive",
            ),
            (
                "sys modules lookup",
                "\nimport sys\n\ndef injected_sys_modules() -> int:\n"
                "    return sys.modules['os'].system('true')\n",
                "namespace lookup|execution primitive",
            ),
            (
                "module dunder attribute",
                "\n\ndef injected_dunder() -> int:\n"
                "    return os.__getattribute__('system')('true')\n",
                "attribute lookup",
            ),
            (
                "operator attrgetter",
                "\nimport operator\n\ndef injected_attrgetter() -> int:\n"
                "    return operator.attrgetter('system')(os)('true')\n",
                "module object",
            ),
        )
        primitive_relative = "tools/round9-eval/cag_round9_external_evaluator.py"
        for label, suffix, error in primitive_mutations:
            with self.subTest(label=label):
                primitive_root = fixture()
                primitive_path = primitive_root / primitive_relative
                primitive_text = primitive_path.read_text(encoding="utf-8") + suffix
                primitive_path.write_text(primitive_text, encoding="utf-8")
                with mock.patch.dict(
                    ROUND9_EVAL_REVIEWED_SCRIPT_SHA256,
                    {primitive_relative: hashlib.sha256(primitive_text.encode("utf-8")).hexdigest()},
                ):
                    with self.assertRaisesRegex(ContractError, error):
                        validate_round9_eval_tool_bundle(primitive_root)

        outside_import_root = fixture()
        outside_module = outside_import_root / "scripts/outside_local.py"
        outside_module.parent.mkdir(parents=True, exist_ok=True)
        outside_module.write_text("VALUE = 1\n", encoding="utf-8")
        outside_import_path = outside_import_root / primitive_relative
        outside_import_text = outside_import_path.read_text(encoding="utf-8") + (
            "\nimport scripts.outside_local\n"
        )
        outside_import_path.write_text(outside_import_text, encoding="utf-8")
        with mock.patch.dict(
            ROUND9_EVAL_REVIEWED_SCRIPT_SHA256,
            {
                primitive_relative: hashlib.sha256(
                    outside_import_text.encode("utf-8")
                ).hexdigest()
            },
        ):
            with self.assertRaisesRegex(ContractError, "exact reviewed allowlist"):
                validate_round9_eval_tool_bundle(outside_import_root)

        decrypt_root = fixture()
        decrypt_relative = "tools/round9-eval/cag_round9_eval_broker.py"
        decrypt_path = decrypt_root / decrypt_relative
        decrypt_original = decrypt_path.read_text(encoding="utf-8")
        self.assertEqual(decrypt_original.count('        str(config["_age"]),\n'), 1)
        decrypt_mutation = decrypt_original.replace(
            '        str(config["_age"]),\n', '        "/bin/sh",\n', 1
        )
        decrypt_path.write_text(decrypt_mutation, encoding="utf-8")
        with mock.patch.dict(
            ROUND9_EVAL_REVIEWED_SCRIPT_SHA256,
            {
                decrypt_relative: hashlib.sha256(
                    decrypt_mutation.encode("utf-8")
                ).hexdigest()
            },
        ), mock.patch.dict(
            ROUND9_EVAL_SUBPROCESS_FUNCTION_CONTRACT,
            {
                decrypt_relative: round9_eval_subprocess_function_contract(
                    decrypt_mutation, decrypt_path
                )
            },
        ):
            with self.assertRaisesRegex(ContractError, "age decrypt argv"):
                validate_round9_eval_tool_bundle(decrypt_root)

        added_call_root = fixture()
        added_call_relative = "tools/round9-eval/round9_eval_test_fixtures.py"
        added_call_path = added_call_root / added_call_relative
        added_call = added_call_path.read_text(encoding="utf-8") + (
            "\n\ndef unreviewed_dynamic_call() -> None:\n"
            "    import subprocess\n"
            "    subprocess.run(['true'], check=False)\n"
        )
        added_call_path.write_text(added_call, encoding="utf-8")
        added_call_hash = hashlib.sha256(added_call.encode("utf-8")).hexdigest()
        with mock.patch.dict(
            ROUND9_EVAL_REVIEWED_SCRIPT_SHA256,
            {added_call_relative: added_call_hash},
        ):
            with self.assertRaisesRegex(ContractError, "subprocess function"):
                validate_round9_eval_tool_bundle(added_call_root)

        extra_path_root = fixture()
        extra_path = extra_path_root / "tools/round9-eval/unreviewed.py"
        extra_path.write_text("raise SystemExit(1)\n", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "path allowlist"):
            validate_round9_eval_tool_bundle(extra_path_root)

        copied_source = repository / "tools/round9-eval/copied_eval_core.py"
        with self.assertRaisesRegex(ContractError, "dynamic Python command"):
            audit_python_source(
                (repository / command_relative).read_text(encoding="utf-8"),
                copied_source,
                repository,
            )

    def test_repository_secret_scan_git_inventory_is_exact_and_path_bound(self):
        repository = Path(__file__).resolve().parent.parent
        source = repository / "scripts/repository_secret_scan.py"
        original = source.read_text(encoding="utf-8")
        audit_python_source(original, source, repository)
        for old, new in (
            ('"ls-files"', '"status"'),
            ("capture_output=True", "capture_output=False"),
            ("check=False", "check=True"),
            ("timeout=30", "timeout=31"),
        ):
            with self.subTest(old=old), self.assertRaisesRegex(
                ContractError,
                "repository secret scanner|dynamic Python command",
            ):
                audit_python_source(
                    original.replace(old, new, 1),
                    source,
                    repository,
                )

    def test_round9_eval_installer_dynamic_dispatch_is_narrowly_reviewed(self):
        root = Path(__file__).resolve().parent.parent
        source = root / "tools/round9-eval/install.sh"
        original = source.read_text(encoding="utf-8")
        self.assertEqual(
            hashlib.sha256(original.encode("utf-8")).hexdigest(),
            ROUND9_EVAL_INSTALL_SCRIPT_SHA256,
        )
        validate_round9_eval_install_script(original, source)
        mutations = (
            (
                "dynamic Python path",
                '  python3 -I -B -m py_compile "$source"',
                '  python3 -I -B "$source"',
            ),
            (
                "nested shell",
                "hash -r\n",
                "hash -r\nbash -c 'true'\n",
            ),
            (
                "eval",
                "hash -r\n",
                'hash -r\neval "$source_dir"\n',
            ),
            (
                "fixed install path",
                'install -o root -g root -m 0755 \\\n  "$broker_source" \\\n  /usr/local/libexec/cag-round9-eval-broker',
                'install -o root -g root -m 0755 \\\n  "$broker_source" \\\n  /tmp/cag-round9-eval-broker',
            ),
        )
        for label, before, after in mutations:
            with self.subTest(label=label):
                self.assertEqual(original.count(before), 1)
                mutation = original.replace(before, after, 1)
                reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.ROUND9_EVAL_INSTALL_SCRIPT_SHA256",
                    reviewed_hash,
                ):
                    with self.assertRaisesRegex(ContractError, "Round 9 evaluator installer"):
                        validate_round9_eval_install_script(mutation, source)

        copied_source = root / "tools/copied-install.sh"
        with self.assertRaisesRegex(ContractError, "outside the reviewed path"):
            validate_round9_eval_install_script(original, copied_source)

    def test_round9_host_evidence_subprocess_is_narrowly_reviewed(self):
        root = Path(__file__).resolve().parent.parent
        source = root / "scripts/round9-host-evidence-test.py"
        original = source.read_text(encoding="utf-8")
        self.assertEqual(
            hashlib.sha256(original.encode("utf-8")).hexdigest(),
            ROUND9_HOST_EVIDENCE_TEST_SCRIPT_SHA256,
        )
        validate_round9_host_evidence_test_script(original, source)
        mutations = (
            (
                "program",
                '                "bash",\n                str(script),',
                '                "sh",\n                str(script),',
            ),
            (
                "environment",
                "            env=env,\n            check=False,",
                "            env=os.environ,\n            check=False,",
            ),
            (
                "check",
                "            env=env,\n            check=False,",
                "            env=env,\n            check=True,",
            ),
            (
                "second subprocess",
                "        result = subprocess.run(\n            [",
                "        subprocess.run(['true'], check=False)\n        result = subprocess.run(\n            [",
            ),
        )
        for label, before, after in mutations:
            with self.subTest(label=label):
                self.assertEqual(original.count(before), 1)
                mutation = original.replace(before, after, 1)
                reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.ROUND9_HOST_EVIDENCE_TEST_SCRIPT_SHA256",
                    reviewed_hash,
                ):
                    with self.assertRaisesRegex(ContractError, "subprocess"):
                        validate_round9_host_evidence_test_script(mutation, source)

        copied_source = root / "scripts/copied-round9-host-evidence-test.py"
        with self.assertRaisesRegex(ContractError, "outside the reviewed path"):
            validate_round9_host_evidence_test_script(original, copied_source)

    def test_round9_host_evidence_runner_command_graph_is_narrowly_reviewed(self):
        root = Path(__file__).resolve().parent.parent
        source = root / "scripts/round9_host_evidence.py"
        original = source.read_text(encoding="utf-8")
        self.assertEqual(
            hashlib.sha256(original.encode("utf-8")).hexdigest(),
            ROUND9_HOST_EVIDENCE_SCRIPT_SHA256,
        )
        self.assertEqual(
            round9_host_evidence_command_function_contract(original, source),
            ROUND9_HOST_EVIDENCE_COMMAND_FUNCTION_CONTRACT,
        )
        validate_round9_host_evidence_script(original, source)

        structural_mutations = (
            (
                "program",
                "            args,\n            stdout=subprocess.PIPE,",
                '            ["bash", "-c", *args],\n            stdout=subprocess.PIPE,',
            ),
            (
                "environment",
                "            stderr=subprocess.PIPE,\n            timeout=timeout,",
                "            stderr=subprocess.PIPE,\n            env=os.environ,\n            timeout=timeout,",
            ),
            (
                "working directory",
                "            stderr=subprocess.PIPE,\n            timeout=timeout,",
                "            stderr=subprocess.PIPE,\n            cwd=Path('/tmp'),\n            timeout=timeout,",
            ),
            (
                "timeout",
                "            timeout=timeout,\n            check=False,",
                "            timeout=120,\n            check=False,",
            ),
            (
                "check",
                "            timeout=timeout,\n            check=False,",
                "            timeout=timeout,\n            check=True,",
            ),
            (
                "shell",
                "            timeout=timeout,\n            check=False,",
                "            timeout=timeout,\n            shell=True,\n            check=False,",
            ),
            (
                "second subprocess",
                "    try:\n        result = subprocess.run(",
                "    try:\n        subprocess.run(['true'], check=False)\n        result = subprocess.run(",
            ),
        )
        for label, before, after in structural_mutations:
            with self.subTest(label=label):
                self.assertEqual(original.count(before), 1)
                mutation = original.replace(before, after, 1)
                reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
                reviewed_contract = round9_host_evidence_command_function_contract(
                    mutation, source
                )
                with mock.patch(
                    "round6_safe_gate_contract.ROUND9_HOST_EVIDENCE_SCRIPT_SHA256",
                    reviewed_hash,
                ), mock.patch(
                    "round6_safe_gate_contract.ROUND9_HOST_EVIDENCE_COMMAND_FUNCTION_CONTRACT",
                    reviewed_contract,
                ):
                    with self.assertRaisesRegex(ContractError, "subprocess contract"):
                        validate_round9_host_evidence_script(mutation, source)

        helper_mutation = original.replace(
            'return run_command(["docker", *args], label=label, timeout=timeout, check=check)',
            'return run_command(["bash", "-c", *args], label=label, timeout=timeout, check=check)',
            1,
        )
        self.assertNotEqual(helper_mutation, original)
        helper_contract = round9_host_evidence_command_function_contract(
            helper_mutation, source
        )
        with mock.patch(
            "round6_safe_gate_contract.ROUND9_HOST_EVIDENCE_SCRIPT_SHA256",
            hashlib.sha256(helper_mutation.encode("utf-8")).hexdigest(),
        ), mock.patch(
            "round6_safe_gate_contract.ROUND9_HOST_EVIDENCE_COMMAND_FUNCTION_CONTRACT",
            helper_contract,
        ):
            with self.assertRaisesRegex(ContractError, "subprocess contract"):
                validate_round9_host_evidence_script(helper_mutation, source)

        copied_source = root / "scripts/copied-round9_host_evidence.py"
        with self.assertRaisesRegex(ContractError, "outside the reviewed path"):
            validate_round9_host_evidence_script(original, copied_source)

    def test_round9_machine_report_test_git_subprocess_is_narrowly_reviewed(self):
        root = Path(__file__).resolve().parent.parent
        source = root / "scripts/round9_machine_reports_test.py"
        original = source.read_text(encoding="utf-8")
        self.assertEqual(
            hashlib.sha256(original.encode("utf-8")).hexdigest(),
            ROUND9_MACHINE_REPORT_TEST_SCRIPT_SHA256,
        )
        validate_round9_machine_report_test_script(original, source)
        mutations = (
            (
                "program",
                '["git", "-C", str(root), *arguments],',
                '["sh", "-c", *arguments],',
            ),
            (
                "environment",
                "            stderr=subprocess.PIPE,\n            text=True,",
                "            stderr=subprocess.PIPE,\n            env=os.environ,\n            text=True,",
            ),
            (
                "working directory",
                "            stderr=subprocess.PIPE,\n            text=True,",
                "            stderr=subprocess.PIPE,\n            cwd=Path('/tmp'),\n            text=True,",
            ),
            (
                "check",
                "            check=True,\n            stdout=subprocess.PIPE,",
                "            check=False,\n            stdout=subprocess.PIPE,",
            ),
            (
                "second subprocess",
                "        result = subprocess.run(\n",
                "        subprocess.run(['true'], check=False)\n        result = subprocess.run(\n",
            ),
        )
        for label, before, after in mutations:
            with self.subTest(label=label):
                self.assertEqual(original.count(before), 1)
                mutation = original.replace(before, after, 1)
                with mock.patch(
                    "round6_safe_gate_contract.ROUND9_MACHINE_REPORT_TEST_SCRIPT_SHA256",
                    hashlib.sha256(mutation.encode("utf-8")).hexdigest(),
                ):
                    with self.assertRaisesRegex(ContractError, "subprocess"):
                        validate_round9_machine_report_test_script(mutation, source)

        copied_source = root / "scripts/copied-round9_machine_reports_test.py"
        with self.assertRaisesRegex(ContractError, "outside the reviewed path"):
            validate_round9_machine_report_test_script(original, copied_source)

    def test_round9_docker_sandbox_subprocess_is_narrowly_reviewed(self):
        root = Path(__file__).resolve().parent.parent
        source = root / "scripts/round9_docker_sandbox.py"
        original = source.read_text(encoding="utf-8")
        self.assertEqual(
            hashlib.sha256(original.encode("utf-8")).hexdigest(),
            ROUND9_DOCKER_SANDBOX_SCRIPT_SHA256,
        )
        self.assertEqual(
            round9_eval_subprocess_function_contract(original, source),
            ROUND9_DOCKER_SANDBOX_SUBPROCESS_CONTRACT,
        )
        validate_round9_docker_sandbox_script(original, source)
        mutations = (
            (
                "program",
                '["docker", *args],',
                '["sh", "-c", *args],',
            ),
            (
                "environment",
                "            stderr=subprocess.PIPE,\n            timeout=timeout,",
                "            stderr=subprocess.PIPE,\n            env=os.environ,\n            timeout=timeout,",
            ),
            (
                "working directory",
                "            stderr=subprocess.PIPE,\n            timeout=timeout,",
                "            stderr=subprocess.PIPE,\n            cwd=Path('/tmp'),\n            timeout=timeout,",
            ),
            (
                "timeout",
                "            timeout=timeout,\n            check=False,",
                "            timeout=30,\n            check=False,",
            ),
            (
                "check",
                "            timeout=timeout,\n            check=False,",
                "            timeout=timeout,\n            check=True,",
            ),
            (
                "shell",
                "            timeout=timeout,\n            check=False,",
                "            timeout=timeout,\n            shell=True,\n            check=False,",
            ),
            (
                "second subprocess",
                "        completed = subprocess.run(\n",
                "        subprocess.run(['true'], check=False)\n        completed = subprocess.run(\n",
            ),
        )
        for label, before, after in mutations:
            with self.subTest(label=label):
                self.assertEqual(original.count(before), 1)
                mutation = original.replace(before, after, 1)
                with mock.patch(
                    "round6_safe_gate_contract.ROUND9_DOCKER_SANDBOX_SCRIPT_SHA256",
                    hashlib.sha256(mutation.encode("utf-8")).hexdigest(),
                ):
                    with self.assertRaisesRegex(ContractError, "subprocess|shell dispatch"):
                        validate_round9_docker_sandbox_script(mutation, source)

        copied_source = root / "scripts/copied-round9_docker_sandbox.py"
        with self.assertRaisesRegex(ContractError, "outside the reviewed path"):
            validate_round9_docker_sandbox_script(original, copied_source)

    def test_rc_source_archive_transient_artifact_pattern_is_precise(self):
        forbidden = (
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
        )
        safe = (
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
        )
        pattern = re.compile(RC_SOURCE_ARCHIVE_TRANSIENT_PATH_PATTERN, re.IGNORECASE)
        test_binary_pattern = re.compile(
            RC_SOURCE_ARCHIVE_TEST_BINARY_PATH_PATTERN, re.IGNORECASE
        )
        safe_test_source_pattern = re.compile(
            RC_SOURCE_ARCHIVE_SAFE_TEST_SOURCE_PATTERN, re.IGNORECASE
        )
        backup_binary_archive_pattern = re.compile(
            RC_SOURCE_ARCHIVE_BACKUP_BINARY_ARCHIVE_PATH_PATTERN, re.IGNORECASE
        )

        def forbidden_path(relative: str) -> bool:
            path = f"cyber-abuse-guard-fixture/{relative}"
            return (
                backup_binary_archive_pattern.search(path) is not None
                or pattern.search(path) is not None
                or (
                    test_binary_pattern.search(path) is not None
                    and safe_test_source_pattern.search(path) is None
                )
            )

        for relative in forbidden:
            with self.subTest(forbidden=relative):
                self.assertTrue(forbidden_path(relative))
        for relative in safe:
            with self.subTest(safe=relative):
                self.assertFalse(forbidden_path(relative))

    def test_rc_source_archive_transient_guard_is_semantically_locked(self):
        root = Path(__file__).parent.parent
        source = root / "scripts/round6-rc-artifacts.sh"
        original = source.read_text(encoding="utf-8")
        validate_rc_source_archive_transient_guard(original, source)
        backup_alternatives = ("bak", "backup", "so", "dll", "zip", "tar", "tgz", "gz")
        backup_pattern = "(" + "|".join(backup_alternatives) + ")"
        backup_mutations = tuple(
            original.replace(
                backup_pattern,
                "("
                + "|".join(
                    candidate
                    for candidate in backup_alternatives
                    if candidate != removed
                )
                + ")",
                1,
            )
            for removed in backup_alternatives
        )
        mutations = backup_mutations + (
            original.replace(
                "(cpu|mem|pprof|test\\.exe|exe)",
                "(cpu|mem|pprof)",
                1,
            ),
            original.replace(
                '  if grep -Eiq "$backup_binary_archive_path_pattern" <<<"$listing" ||',
                '  if false && grep -Eiq "$backup_binary_archive_path_pattern" <<<"$listing" ||',
                1,
            ),
            original.replace(
                '    grep -Eiq "$transient_path_pattern" <<<"$listing" ||',
                '    false && grep -Eiq "$transient_path_pattern" <<<"$listing" ||',
                1,
            ),
            original.replace(
                "  local safe_test_source_pattern='(^|/)Dockerfile\\.test($|/)'\n",
                "  local safe_test_source_pattern='(^|/)[^/]*\\.test($|/)'\n",
                1,
            ),
            original.replace(
                RC_SOURCE_ARCHIVE_TRANSIENT_GUARD_BLOCK + "\n",
                "",
                1,
            ).replace(
                '  mv -f -- "$temporary" "$output_dir/$source_archive"',
                '  mv -f -- "$temporary" "$output_dir/$source_archive"\n'
                + RC_SOURCE_ARCHIVE_TRANSIENT_GUARD_BLOCK,
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertNotEqual(mutation, original)
                with self.assertRaisesRegex(
                    ContractError,
                    "backup/binary/archive|transient-artifact|test-binary allow boundary|fail closed",
                ):
                    validate_rc_source_archive_transient_guard(mutation, source)

    def test_reproducibility_package_release_cannot_escape_formal_branch(self):
        original, source = self.reproducibility_script()
        mutations = (
            original.replace(
                '  if [[ "$RELEASE_BUILD_KIND" == formal ]]; then\n'
                '    env "${common_env[@]}" "$clone/scripts/package-release.sh"\n',
                '  if [[ "$RELEASE_BUILD_KIND" == candidate ]]; then\n'
                '    env "${common_env[@]}" "$clone/scripts/package-release.sh"\n',
                1,
            ),
            original.replace(
                '    env "${common_env[@]}" "$clone/scripts/package-release.sh"\n',
                "    true\n",
                1,
            )
            + 'env "${common_env[@]}" "$clone/scripts/package-release.sh"\n',
        )
        for text in mutations:
            self.assertNotEqual(text, original)
            with self.assertRaisesRegex(ContractError, "formal-only branch"):
                validate_round6_reproducibility_script(text, source)

    def test_reproducibility_checksums_manifest_is_generated_and_compared(self):
        original, source = self.reproducibility_script()
        mutations = (
            original.replace("        sbom.cdx.json >checksums.txt\n", "", 1),
            original.replace(
                'compare_artifact "checksums manifest" checksums.txt\n', "", 1
            ),
            original.replace(" build-metadata.json checksums.txt \\\n", " build-metadata.json \\\n", 1),
        )
        for text in mutations:
            self.assertNotEqual(text, original)
            with self.assertRaisesRegex(ContractError, "checksums manifest"):
                validate_round6_reproducibility_script(text, source)

    def test_reproducibility_wrapper_is_exact_and_only_delegates(self):
        source = Path(__file__).with_name("reproducibility-test.sh")
        text = source.read_text(encoding="utf-8")
        validate_reproducibility_wrapper_script(text, source)
        with self.assertRaisesRegex(ContractError, "exact reviewed"):
            validate_reproducibility_wrapper_script(text + "\ntrue\n", source)

    def test_frozen_evaluation_tree_verifier_is_exact_metadata_only_contract(self):
        source = Path(__file__).with_name("verify-frozen-evaluation-v10-tree.sh")
        text = source.read_text(encoding="utf-8")
        validate_frozen_evaluation_tree_script(text, source)
        with self.assertRaisesRegex(ContractError, "metadata-only contract"):
            validate_frozen_evaluation_tree_script(text + "\ntrue\n", source)
        without_untracked = text.replace("--untracked-files=all", "--untracked-files=no", 1)
        self.assertNotEqual(without_untracked, text)
        with self.assertRaisesRegex(ContractError, "staged, unstaged, and untracked"):
            validate_frozen_evaluation_tree_script(without_untracked, source)

    def test_round6_privacy_and_document_fixture_hashes_are_frozen(self):
        root = Path(__file__).parent.parent
        privacy = root / "scripts/release-evidence-privacy-test.sh"
        privacy_text = privacy.read_text(encoding="utf-8")
        validate_round6_privacy_fixture_script(privacy_text, privacy)
        with self.assertRaisesRegex(ContractError, "privacy fixture"):
            validate_round6_privacy_fixture_script(privacy_text + "\ntrue\n", privacy)

        wrapper = root / "scripts/round6-doc-consistency-fixture-test.sh"
        wrapper_text = wrapper.read_text(encoding="utf-8")
        validate_round6_doc_fixture_wrapper_script(wrapper_text, wrapper, root)
        with self.assertRaisesRegex(ContractError, "document fixture wrapper"):
            validate_round6_doc_fixture_wrapper_script(
                wrapper_text + "\ntrue\n", wrapper, root
            )
        for pin_name in ("expected_fixture_sha256", "expected_gate_sha256"):
            with self.subTest(pin_name=pin_name):
                mutated = re.sub(
                    rf"(?m)^{pin_name}='[0-9a-f]{{64}}'$",
                    f"{pin_name}='{'0' * 64}'",
                    wrapper_text,
                    count=1,
                )
                self.assertNotEqual(mutated, wrapper_text)
                reviewed_hash = hashlib.sha256(mutated.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.ROUND6_DOC_FIXTURE_WRAPPER_SCRIPT_SHA256",
                    reviewed_hash,
                ):
                    with self.assertRaisesRegex(
                        ContractError, "must pin the reviewed dependency hash"
                    ):
                        validate_round6_doc_fixture_wrapper_script(
                            mutated, wrapper, root
                        )

    def test_cpa_compatibility_separates_pinned_tag_and_optional_latest_proof(self):
        source = Path(__file__).with_name("cpa-latest-compat.sh")
        text = source.read_text(encoding="utf-8")
        validate_cpa_compat_script(text, source)
        mutations = (
            text.replace(
                "remote_tag_verified=1 remote_latest_check=SKIPPED_PINNED_TARGET",
                "remote_tag_check=SKIPPED remote_latest_check=SKIPPED",
                1,
            ),
            text.replace(
                '[[ "$resolved_latest_tag" == "$cpa_version" ]]',
                "true",
                1,
            ),
            text.replace(
                "https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest",
                f"https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/tags/{CPA_CURRENT_VERSION}",
                1,
            ),
        )
        for mutation in mutations:
            self.assertNotEqual(mutation, text)
            with self.assertRaisesRegex(
                ContractError,
                "latest Release|official Release|optional latest|pinned tag proof|repository token",
            ):
                validate_cpa_compat_script(mutation, source)

    def test_cpa_compatibility_pins_selected_toolchain_before_cache_isolation(self):
        source = Path(__file__).with_name("cpa-latest-compat.sh")
        text = source.read_text(encoding="utf-8")
        validate_cpa_compat_script(text, source)
        mutations = (
            text.replace(
                'selected_go_root="$("$go_launcher" -C "$root" env GOROOT)"',
                'selected_go_root="$("$go_launcher" env GOROOT)"',
                1,
            ),
            text.replace('go_bin="$selected_go_root/bin/go"', 'go_bin="$go_launcher"', 1),
            text.replace(
                "export GOTOOLCHAIN=go1.26.4",
                "export GOTOOLCHAIN=go1.26.04 # lookalike",
                1,
            ),
            text.replace("export GOFLAGS=-mod=readonly", "export GOFLAGS=-mod=mod", 1),
            text.replace(
                '"$cpa_module/sdk/pluginabi"',
                '"$cpa_module/sdk/unreviewedabi"',
                1,
            ),
            text.replace(
                '"$cpa_module/sdk/pluginapi"',
                '"$cpa_module/sdk/unreviewedapi"',
                1,
            ),
        )
        for mutation in mutations:
            self.assertNotEqual(mutation, text)
            reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
            with mock.patch(
                "round6_safe_gate_contract.CPA_COMPAT_SCRIPT_SHA256", reviewed_hash
            ):
                with self.assertRaisesRegex(
                    ContractError, "selected Go toolchain|lightweight tag"
                ):
                    validate_cpa_compat_script(mutation, source)

    def test_cpa_remote_checks_pin_http11_and_bounded_retries(self):
        source = Path(__file__).with_name("cpa-latest-compat.sh")
        text = source.read_text(encoding="utf-8")
        validate_cpa_compat_script(text, source)
        mutations = (
            text.replace("-c http.version=HTTP/1.1", "-c http.version=HTTP/2", 1),
            text.replace("for attempt in 1 2 3; do", "for attempt in 1; do", 1),
            text.replace(
                "--retry 2 --retry-delay 2 --retry-max-time 55",
                "--retry 0 --retry-delay 2 --retry-max-time 55",
                1,
            ),
            text.replace(
                "--fail --silent --show-error --location --http1.1",
                "--fail --silent --show-error --location",
                1,
            ),
        )
        for mutation in mutations:
            self.assertNotEqual(mutation, text)
            reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
            with mock.patch(
                "round6_safe_gate_contract.CPA_COMPAT_SCRIPT_SHA256", reviewed_hash
            ):
                with self.assertRaisesRegex(
                    ContractError, "lightweight tag|bounded retries|official Release"
                ):
                    validate_cpa_compat_script(mutation, source)

    def test_checked_in_cpa_module_pins_cannot_drift(self):
        source_root = Path(__file__).resolve().parent.parent
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture_root = Path(temporary.name)
        module_files = (
            "go.mod",
            "go.sum",
            "integration/cpalatestcontract/go.mod",
            "integration/cpalatestcontract/go.sum",
            "integration/pluginstorecontract/go.mod",
            "integration/pluginstorecontract/go.sum",
        )
        for relative in module_files:
            target = fixture_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source_root / relative).read_bytes())
        validate_cpa_module_pins(fixture_root)

        module_versions = {
            "go.mod": CPA_CURRENT_VERSION,
            "integration/cpalatestcontract/go.mod": CPA_CURRENT_VERSION,
            "integration/pluginstorecontract/go.mod": CPA_CURRENT_VERSION,
        }
        for relative, version in module_versions.items():
            with self.subTest(relative=relative):
                target = fixture_root / relative
                original = target.read_text(encoding="utf-8")
                target.write_text(
                    original.replace(
                        f"github.com/router-for-me/CLIProxyAPI/v7 {version}",
                        "github.com/router-for-me/CLIProxyAPI/v7 v7.2.99",
                        1,
                    ),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ContractError, "checked-in CPA module pin"):
                    validate_cpa_module_pins(fixture_root)
                target.write_text(original, encoding="utf-8")

        sum_path = fixture_root / "go.sum"
        original_sum = sum_path.read_text(encoding="utf-8")
        sum_path.write_text(
            original_sum.replace(
                f"github.com/router-for-me/CLIProxyAPI/v7 {CPA_CURRENT_VERSION} {CPA_CURRENT_MODULE_SUM}",
                f"github.com/router-for-me/CLIProxyAPI/v7 {CPA_CURRENT_VERSION} h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ContractError, "checked-in CPA sums"):
            validate_cpa_module_pins(fixture_root)

        sum_path.write_text(original_sum, encoding="utf-8")
        primary_go_mod_sum = (
            f"github.com/router-for-me/CLIProxyAPI/v7 {CPA_CURRENT_VERSION}/go.mod "
            f"{CPA_CURRENT_GO_MOD_SUM}"
        )
        sum_path.write_text(
            original_sum.replace(
                primary_go_mod_sum,
                f"github.com/router-for-me/CLIProxyAPI/v7 {CPA_CURRENT_VERSION}/go.mod "
                "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ContractError, "checked-in CPA sums"):
            validate_cpa_module_pins(fixture_root)

        sum_path.write_text(original_sum, encoding="utf-8")
        store_sum_path = fixture_root / "integration/pluginstorecontract/go.sum"
        original_store_sum = store_sum_path.read_text(encoding="utf-8")
        store_sum_path.write_text(
            original_store_sum.replace(
                f"github.com/router-for-me/CLIProxyAPI/v7 {CPA_CURRENT_VERSION}/go.mod "
                f"{CPA_CURRENT_GO_MOD_SUM}",
                f"github.com/router-for-me/CLIProxyAPI/v7 {CPA_CURRENT_VERSION}/go.mod "
                "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ContractError, "checked-in CPA sums"):
            validate_cpa_module_pins(fixture_root)

    def test_cpa_compatibility_remote_control_flow_is_frozen(self):
        source = Path(__file__).with_name("cpa-latest-compat.sh")
        text = source.read_text(encoding="utf-8")
        mutations = (
            text + "\n: <<'ROUND6_INERT'\nremote check bypass fixture\nROUND6_INERT\n",
            text.replace(
                'if [[ "$verify_remote" == 1 ]]; then\n'
                '  command -v git >/dev/null 2>&1 || {',
                'if false; then\n'
                '  command -v git >/dev/null 2>&1 || {',
                1,
            ),
            text.replace('git -C "$git_identity_dir" \\\n', 'git \\\n', 1),
            text.replace(
                'if [[ "$verify_remote" == 1 && "$require_latest" == 1 && "$verify_primary_latest" == 1 ]]; then',
                "if false; then",
                1,
            ),
            text.replace(
                'if [[ "$require_latest" == 1 && "$verify_remote" != 1 ]]; then',
                "if false; then",
                1,
            ),
            text.replace(
                'resolved_latest_tag="$(resolve_remote_latest_release_tag)"',
                'resolved_latest_tag="$cpa_version"',
                1,
            ),
        )
        for mutation in mutations:
            self.assertNotEqual(mutation, text)
            with self.assertRaisesRegex(
                ContractError,
                "exact reviewed remote-verification contract|bind the exact lightweight tag|latest Release|optional latest",
            ):
                validate_cpa_compat_script(mutation, source)
        semantic_mutations = (
            text.replace(
                '[[ "$resolved_latest_tag" == "$cpa_version" ]]',
                "true",
                1,
            ),
            text.replace('[[ "$refs" == "$expected" ]]', "true", 1),
            text.replace(
                '     "$download_sum" == "$cpa_module_sum" && \\\n',
                "     true && \\\n",
                1,
            ),
            text.replace(
                '     "$download_go_mod_sum" == "$cpa_go_mod_sum" ]] || {',
                "     true ]] || {",
                1,
            ),
            text.replace(
                '     "$download_origin_url" == "$cpa_origin_url" && \\\n',
                "     true && \\\n",
                1,
            ),
            text.replace(
                '     "$download_origin_hash" == "$cpa_commit" && \\\n',
                "     true && \\\n",
                1,
            ),
            text.replace(
                '     "$download_origin_ref" == "refs/tags/$cpa_version" ]] || {',
                "     true ]] || {",
                1,
            ),
        )
        for mutation in semantic_mutations:
            self.assertNotEqual(mutation, text)
            reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
            with mock.patch(
                "round6_safe_gate_contract.CPA_COMPAT_SCRIPT_SHA256", reviewed_hash
            ):
                with self.assertRaisesRegex(
                    ContractError, "lightweight tag|Origin|latest Release"
                ):
                    validate_cpa_compat_script(mutation, source)

    def test_cpa_primary_profile_is_exclusive(self):
        source = Path(__file__).with_name("cpa-latest-compat.sh")
        text = source.read_text(encoding="utf-8")
        mutations = (
            text.replace("profiles=(primary)", "profiles=(primary compatibility)", 1),
            text.replace(
                'requested_profile="${CPA_COMPAT_PROFILE:-primary}"',
                'requested_profile="${CPA_COMPAT_PROFILE:-all}"',
                1,
            ),
        )
        for mutation in mutations:
            self.assertNotEqual(mutation, text)
            reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
            with mock.patch(
                "round6_safe_gate_contract.CPA_COMPAT_SCRIPT_SHA256", reviewed_hash
            ):
                with self.assertRaisesRegex(
                    ContractError, "bind the exact lightweight tag"
                ):
                    validate_cpa_compat_script(mutation, source)

    def test_cpa_compatibility_requires_official_latest_api_without_repository_tokens(self):
        source = Path(__file__).with_name("cpa-latest-compat.sh")
        text = source.read_text(encoding="utf-8")
        validate_cpa_compat_script(text, source)
        for forbidden in (
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "${{ github.token }}",
            "Authorization:",
            "releases/tags",
        ):
            with self.subTest(forbidden=forbidden):
                mutation = text + f"\n# {forbidden}\n"
                with self.assertRaisesRegex(
                    ContractError, "must not use a repository token or authenticated release metadata"
                ):
                    validate_cpa_compat_script(mutation, source)

    def test_linux_build_glibc_contract_passes(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        validate_round6_linux_build_script(source.read_text(encoding="utf-8"), source)

    def test_linux_build_glibc_contract_bypass_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        text = source.read_text(encoding="utf-8").replace(
            '"$(printf \'%s\\n\' "$max_glibc" \'2.34\' | sort -V | tail -1)" != 2.34',
            '"$(printf \'%s\\n\' "$max_glibc" \'2.35\' | sort -V | tail -1)" != 2.35',
        )
        with self.assertRaisesRegex(ContractError, "glibc 2.34"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_glibc_missing_exit_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace(
            "  printf 'build requires unsupported glibc %s; maximum allowed is 2.34\\n' \"$max_glibc\" >&2\n"
            "  exit 1\n",
            "  printf 'build requires unsupported glibc %s; maximum allowed is 2.34\\n' \"$max_glibc\" >&2\n",
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_glibc_if_false_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace('file "$artifact"\n', 'if false; then\nfile "$artifact"\n').replace(
            '(cd "$dist" && sha256sum -c "$(basename "$artifact").sha256")\n',
            '(cd "$dist" && sha256sum -c "$(basename "$artifact").sha256")\nfi\n',
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34|control wrapper"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_glibc_or_true_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace('  LC_ALL=C sort -u)"\n', '  LC_ALL=C sort -u)" || true\n', 1)
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34|success bypass"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_set_plus_e_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace("set -euo pipefail\n", "set -euo pipefail\nset +e\n", 1)
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_bare_exit_before_checks_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace(
            'OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-build-metadata.sh"\n',
            'exit\nOUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-build-metadata.sh"\n',
            1,
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34"):
            validate_round6_linux_build_script(text, source)

    def test_linux_build_allowed_if_wrapper_still_fails(self):
        source = Path(__file__).with_name("build-linux-amd64.sh")
        original = source.read_text(encoding="utf-8")
        text = original.replace(
            'OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-build-metadata.sh"\n',
            'if [[ "$go_version" != go1.26.4 ]]; then\n'
            'OUTPUT_DIR="$dist" GO="$go_bin" "$root/scripts/release-build-metadata.sh"\n',
            1,
        ).replace(
            'release_assert_source_unchanged\n',
            'release_assert_source_unchanged\nfi\n',
            1,
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "exact glibc 2.34"):
            validate_round6_linux_build_script(text, source)

    def test_round6_benchmark_contract_passes(self):
        source = Path(__file__).parent.parent / "Makefile"
        validate_round6_makefile_contract(source.read_text(encoding="utf-8"), source)

    def test_benchmark_parent_requires_profiled_candidate_performance_bound(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        text = original.replace(
            "TestCandidateRichProfiledMaxPartsPerformanceBound",
            "TestMissingCandidateRichProfiledMaxPartsPerformanceBound",
            1,
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "classifier hard bounds"):
            validate_round6_makefile_contract(text, source)

    def test_fuzz_smoke_requires_exact_fail_closed_seed_targets(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        mutations = (
            original.replace(
                "FuzzRound6StreamingChunkAndRoleBoundaries",
                "FuzzMissingStreamingChunkAndRoleBoundaries",
                1,
            ),
            original.replace(
                "$(GO) test ./internal/config -run='^FuzzConfigParser$$' -count=1",
                "$(GO) test ./internal/config -run='^$$' -fuzz='^FuzzConfigParser$$' -fuzztime=5s",
                1,
            ),
        )
        for text in mutations:
            self.assertNotEqual(text, original)
            with self.assertRaisesRegex(ContractError, "fuzz-smoke must fail closed"):
                validate_round6_makefile_contract(text, source)

    def test_round9_fuzz_requires_exact_bounded_real_fuzz_targets(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        mutations = (
            original.replace(
                "FuzzRound9AuditDecisionExplanationV2",
                "FuzzMissingRound9AuditDecisionExplanationV2",
                1,
            ),
            original.replace("ROUND9_FUZZTIME ?= 5s", "ROUND9_FUZZTIME ?= 11s", 1),
            original.replace("-parallel=1", "-parallel=2", 1),
            original.replace("GOMAXPROCS=2", "GOMAXPROCS=8", 1),
        )
        for text in mutations:
            self.assertNotEqual(text, original)
            with self.assertRaisesRegex(
                ContractError,
                "round9-fuzz must retain the exact Linux/amd64 Go 1.26.4 bounded real-fuzz contract",
            ):
                validate_round6_makefile_contract(text, source)

    def test_round6_benchmark_requires_scale_acceptance_presence_gate(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        text = original.replace(
            "-list='^TestRound6LongTextScaleAcceptance$$'",
            "-list='^TestMissingRound6LongTextScaleAcceptance$$'",
            1,
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "acceptance plus extract/full-route benchmarks"):
            validate_round6_makefile_contract(text, source)

    def test_round6_benchmark_wrong_package_fails(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        text = original.replace(
            "$(GO) test ./internal/extract -run='^$$' \\\n"
            "\t\t-bench='^BenchmarkRound6ScanLongJSON$$'",
            "$(GO) test ./internal/classifier -run='^$$' \\\n"
            "\t\t-bench='^BenchmarkRound6ScanLongJSON$$'",
            1,
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "acceptance plus extract/full-route benchmarks"):
            validate_round6_makefile_contract(text, source)

    def test_round6_benchmark_missing_full_route_benchmark_fails(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        for benchmark_name in (
            "BenchmarkFourRepositoryModelRoute",
            "BenchmarkFourRepositoryParallelCleanSubjectEnabled",
            "BenchmarkBalancedAuditOnWrapperOnly17166ModelRoute",
        ):
            text = original.replace(benchmark_name, "BenchmarkMissingFullRoute", 1)
            self.assertNotEqual(text, original)
            with self.assertRaisesRegex(ContractError, "full-route benchmarks"):
                validate_round6_makefile_contract(text, source)

    def test_round6_benchmark_missing_full_route_execution_fails(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        command = (
            "\t$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -run='^$$' \\\n"
            "\t\t-bench='^(BenchmarkFourRepositoryModelRoute|BenchmarkFourRepositoryParallelCleanSubjectEnabled|BenchmarkBalancedAuditOnWrapperOnly17166ModelRoute)$$' \\\n"
            "\t\t-benchmem -benchtime=3x -count=1\n"
        )
        text = original.replace(command, "", 1)
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "acceptance plus extract/full-route benchmarks"):
            validate_round6_makefile_contract(text, source)

    def test_round6_benchmark_missing_performance_acceptance_fails(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        text = original.replace(
            "TestFourRepositoryFullRoutePerformanceAcceptance",
            "TestMissingFullRoutePerformanceAcceptance",
            1,
        )
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "acceptance plus extract/full-route benchmarks"):
            validate_round6_makefile_contract(text, source)

    def test_round6_wrapper_audit_fast_path_regression_missing_fails(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        for test_name in (
            "TestBalancedAuditOnWrapperOnlyCounterFastPath",
            "TestWrapperAuditFastPathPreservesSecurityEvents",
            "TestBalancedAuditOnTrustedUserWrapperPersists",
            "TestBalancedAuditOnWrapperOnlyAllocationAcceptance",
        ):
            text = original.replace(test_name, "TestMissingWrapperAuditRegression", 1)
            self.assertNotEqual(text, original)
            with self.assertRaisesRegex(ContractError, "wrapper audit fast-path regression"):
                validate_round6_makefile_contract(text, source)

    def test_round6_wrapper_audit_fast_path_execution_missing_fails(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        command = (
            '\t$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -count=1 -v '
            '-run="^($$pattern)$$"\n'
        )
        text = original.replace(command, "", 1)
        self.assertNotEqual(text, original)
        with self.assertRaisesRegex(ContractError, "wrapper audit plugin pattern"):
            validate_round6_makefile_contract(text, source)

    def test_round6_module_verify_tidy_diff_is_integration_only(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        before, marker, round6 = original.partition("round6-module-verify:")
        self.assertTrue(marker)
        mutations = tuple(
            before + marker + mutation
            for mutation in (
                round6.replace(
                    "\t$(GO) -C integration/round9countedmock mod tidy -diff\n",
                    "",
                    1,
                ),
                round6.replace(
                    "\t$(GO) -C integration/pluginstorecontract mod tidy -diff\n",
                    "",
                    1,
                ),
                round6.replace(
                    "\t$(GO) -C integration/cpalatestcontract mod tidy -diff\n",
                    "",
                    1,
                ),
                round6.replace(
                    "\t$(GO) mod verify\n",
                    "\t$(GO) mod verify\n\t$(GO) mod tidy -diff\n",
                    1,
                ),
                round6.replace(
                    "\t$(GO) -C integration/round9countedmock mod verify\n",
                    "\t$(GO) -C integration/round8countedmock mod verify\n"
                    "\t$(GO) -C integration/round9countedmock mod verify\n",
                    1,
                ),
            )
        )
        for text in mutations:
            self.assertNotEqual(text, original)
            with self.assertRaisesRegex(ContractError, "current integration modules"):
                validate_round6_makefile_contract(text, source)

    def test_round8_counted_mock_isolated_from_active_safe_development_modes(self):
        source = Path(__file__).with_name("go-safe-development-test.sh")
        original = source.read_text(encoding="utf-8")
        validate_round6_go_safe_development_script(original, source)
        mutation = original.replace(
            'round9_counted_mock_module="integration/round9countedmock"\n',
            'round8_counted_mock_module="integration/round8countedmock"\n'
            'round9_counted_mock_module="integration/round9countedmock"\n',
            1,
        )
        self.assertNotEqual(mutation, original)
        with self.assertRaisesRegex(ContractError, "must not execute Round 8 counted-Mock"):
            validate_round6_go_safe_development_script(mutation, source)

    def test_round6_makefile_candidate_script_gates_are_reachable(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        required_lines = (
            "\tmake workflow-lint\n",
            "\tbash -n ./scripts/round6-candidate-artifacts.sh\n",
            "\t./scripts/release-candidate-contract-test.sh\n",
            "\tbash -n ./scripts/verify-external-release-attestation.sh\n",
            "\t./scripts/verify-external-release-attestation-test.sh\n",
        )
        for required_line in required_lines:
            with self.subTest(required_line=required_line.strip()):
                text = original.replace(required_line, "", 1)
                self.assertNotEqual(text, original)
                with self.assertRaisesRegex(ContractError, "reviewed Round6 script gate"):
                    validate_round6_makefile_contract(text, source)

        actionlint_mutations = (
            original.replace(
                "ACTIONLINT_VERSION ?= v1.7.12",
                "ACTIONLINT_VERSION ?= v1.7.11",
                1,
            ),
            original.replace(
                "-config-file .github/actionlint.yaml",
                "-config-file .github/unreviewed-actionlint.yaml",
                1,
            ),
            original.replace(
                ".github/workflows/round8-host-validation.yml",
                ".github/workflows/ci.yml",
                1,
            ),
            original.replace(
                ".github/workflows/release-promote.yml",
                ".github/workflows/*.yml",
                1,
            ),
            original.replace("race workflow-lint", "race", 1),
        )
        for text in actionlint_mutations:
            self.assertNotEqual(text, original)
            with self.assertRaisesRegex(ContractError, "actionlint|workflow-lint"):
                validate_round6_makefile_contract(text, source)

    def test_round6_makefile_runs_privacy_safe_mutation_fixtures(self):
        source = Path(__file__).parent.parent / "Makefile"
        original = source.read_text(encoding="utf-8")
        before, marker, round6 = original.rpartition("round6-script-test:")
        self.assertTrue(marker)
        for required_line in (
            "\tbash ./scripts/release-evidence-privacy-test.sh\n",
            "\tbash ./scripts/round6-doc-consistency-fixture-test.sh\n",
        ):
            with self.subTest(required_line=required_line.strip()):
                mutated_round6 = round6.replace(required_line, "", 1)
                self.assertNotEqual(mutated_round6, round6)
                text = before + marker + mutated_round6
                with self.assertRaisesRegex(ContractError, "privacy-safe mutation fixture"):
                    validate_round6_makefile_contract(text, source)

    def candidate_workflow(self) -> str:
        source = Path(__file__).parent.parent / ".github/workflows/candidate.yml"
        return source.read_text(encoding="utf-8")

    def formal_release_workflow(self) -> str:
        source = Path(__file__).parent.parent / ".github/workflows/release.yml"
        return source.read_text(encoding="utf-8")

    def release_promote_workflow(self) -> str:
        source = Path(__file__).parent.parent / ".github/workflows/release-promote.yml"
        return source.read_text(encoding="utf-8")

    def rc_release_workflow(self) -> str:
        source = Path(__file__).parent.parent / ACTIVE_RC_WORKFLOW_PATH
        return source.read_text(encoding="utf-8")

    def codeql_workflow(self) -> str:
        source = Path(__file__).parent.parent / ".github/workflows/codeql.yml"
        return source.read_text(encoding="utf-8")

    def workflow_layout_fixture(self) -> Path:
        source_root = Path(__file__).resolve().parent.parent
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative in (
            ACTIONLINT_CONFIG_PATH,
            *ACTIVE_WORKFLOW_PATHS,
            *WORKFLOW_DIRECTORY_AUXILIARY_PATHS,
            ARCHIVED_RC_WORKFLOW_PATH,
        ):
            source = source_root / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        return root

    def test_workflow_layout_has_exact_eleven_active_entrypoints_and_archived_rc(self):
        root = Path(__file__).resolve().parent.parent
        validate_workflow_layout(root)
        entrypoints = default_entrypoints(root)
        self.assertEqual(
            tuple(path.relative_to(root).as_posix() for path in entrypoints),
            ACTIVE_WORKFLOW_PATHS,
        )
        archive = (root / ARCHIVED_RC_WORKFLOW_PATH).resolve()
        active_directory = (root / ".github/workflows").resolve()
        self.assertFalse(archive.is_relative_to(active_directory))
        self.assertNotIn(archive, {path.resolve() for path in entrypoints})
        self.assertTrue((active_directory / "release-rc.yml").is_file())
        self.assertTrue((active_directory / "round8-host-validation.yml").is_file())

    def test_workflow_layout_rejects_extra_entrypoint_and_archived_rc_mutation(self):
        root = self.workflow_layout_fixture()
        extra = root / ".github/workflows/unreviewed.yml"
        extra.write_text("name: Unreviewed\n", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "exactly the eleven reviewed entrypoints"):
            validate_workflow_layout(root)
        extra.unlink()

        missing = root / ACTIVE_WORKFLOW_PATHS[1]
        missing_bytes = missing.read_bytes()
        missing.unlink()
        with self.assertRaisesRegex(ContractError, "exactly the eleven reviewed entrypoints"):
            validate_workflow_layout(root)
        missing.write_bytes(missing_bytes)

        actionlint_config = root / ACTIONLINT_CONFIG_PATH
        original_actionlint_config = actionlint_config.read_text(encoding="utf-8")
        actionlint_mutations = (
            original_actionlint_config.replace(
                "cag-round8-sandbox", "unreviewed-runner-label", 1
            ),
            original_actionlint_config + "unexpected-root-key: true\n",
            original_actionlint_config.replace(
                "    - cag-round8-sandbox\n",
                "    - cag-round8-sandbox\n    - unreviewed-runner-label\n",
                1,
            ),
        )
        for mutation in actionlint_mutations:
            with self.subTest(actionlint_mutation=mutation):
                actionlint_config.write_text(mutation, encoding="utf-8")
                with self.assertRaisesRegex(ContractError, "actionlint"):
                    validate_workflow_layout(root)
        actionlint_config.write_text(original_actionlint_config, encoding="utf-8")

        archive = root / ARCHIVED_RC_WORKFLOW_PATH
        archive.write_text(archive.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "archived RC workflow differs"):
            validate_workflow_layout(root)

    def test_active_workflow_display_names_are_exact(self):
        candidate = self.candidate_workflow().replace(
            "name: Candidate build - NOT A RELEASE\n",
            "name: Renamed candidate\n",
            1,
        )
        with self.assertRaisesRegex(ContractError, "exact scalar"):
            validate_candidate_workflow(candidate, Path("candidate.yml"))

        attested = self.blocked_workflow().replace(
            "name: Attested prerelease - HOST, AUDIT, AND EVALUATION REQUIRED\n",
            "name: Renamed attested prerelease\n",
            1,
        )
        with self.assertRaisesRegex(ContractError, "exact scalar"):
            validate_blocked_prerelease_workflow(
                attested, Path("attested-prerelease.yml")
            )

    def test_codeql_workflow_is_exact_and_rejects_permission_trigger_or_action_drift(self):
        source = Path(__file__).parent.parent / ".github/workflows/codeql.yml"
        original = self.codeql_workflow()
        validate_codeql_workflow(original, source)
        mutations = (
            original.replace("  contents: read\n", "  contents: write\n", 1),
            original.replace("  pull_request:\n", "  pull_request_target:\n", 1),
            original.replace(
                "github/codeql-action/analyze@7188fc363630916deb702c7fdcf4e481b751f97a",
                "github/codeql-action/analyze@" + "0" * 40,
                1,
            ),
            original.replace("      security-events: write\n", "      security-events: read\n", 1),
            original.replace(
                "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
                "actions/setup-go@" + "0" * 40,
                1,
            ),
            original.replace("          build-mode: manual\n", "          build-mode: none\n", 1),
            original.replace(
                "        run: go build -mod=readonly -tags=sqlite_omit_load_extension "
                "./cmd/cyber-abuse-guard ./internal/... ./rules\n",
                "        run: go build ./...\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "CodeQL workflow differs"):
                validate_codeql_workflow(workflow, source)

    def test_candidate_workflow_full_contract_passes(self):
        validate_candidate_workflow(
            self.candidate_workflow(), Path("candidate.yml")
        )

    def test_candidate_workflow_must_remain_manual_and_read_only(self):
        original = self.candidate_workflow()
        mutations = (
            original.replace("  workflow_dispatch:\n", "  push:\n", 1),
            original.replace("  contents: read\n", "  contents: write\n", 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "manual-only|read|exact scalar"):
                validate_candidate_workflow(workflow, Path("candidate.yml"))

    def test_candidate_workflow_exact_commit_and_push_ci_binding_are_locked(self):
        original = self.candidate_workflow()
        protected_lines = (
            '          [[ "$DISPATCH_REF" == "refs/heads/main" ]]\n',
            '          [[ "$DISPATCH_SHA" == "$EXPECTED_COMMIT" ]]\n',
            '             .event == "push" and\n',
            '             .head_sha == $expected_commit and\n',
            '             .conclusion == "success" and\n',
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed text"):
                    validate_candidate_workflow(workflow, Path("candidate.yml"))

    def test_candidate_workflow_sparse_boundary_and_gate_are_locked(self):
        original = self.candidate_workflow()
        mutations = (
            original.replace("            !/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*\n", "", 1),
            original.replace(
                "          python3 -B scripts/round6_safe_gate_contract.py --root .\n",
                "          true\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "sparse|safe-gate"):
                validate_candidate_workflow(workflow, Path("candidate.yml"))

    def test_candidate_workflow_consumed_boundary_is_locked(self):
        original = self.candidate_workflow()
        workflow = original.replace(
            "            !/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*\n", "", 1
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "sparse"):
            validate_candidate_workflow(workflow, Path("candidate.yml"))

    def test_candidate_builder_reproducibility_and_clean_names_are_locked(self):
        original = self.candidate_workflow()
        mutations = (
            original.replace(
                "        run: ./scripts/round6-candidate-artifacts.sh\n",
                "        run: true\n",
                1,
            ),
            original.replace(
                "        run: make round6-reproducibility-test\n",
                "        run: make clean-tree-check\n",
                1,
            ),
            original.replace(
                "            dist/cyber-abuse-guard_0.15_linux_amd64.zip\n",
                "            dist/nested/cyber-abuse-guard_0.15-dirty_linux_amd64.zip\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "exact reviewed text|artifact allowlist"):
                validate_candidate_workflow(workflow, Path("candidate.yml"))

    def test_candidate_workflow_rejects_release_or_token_expansion(self):
        original = self.candidate_workflow()
        release_action = original.replace(
            "      - name: Upload private exact-commit candidate\n",
            "      - name: Publish candidate\n"
            "        uses: softprops/action-gh-release@0123456789abcdef0123456789abcdef01234567\n"
            "      - name: Upload private exact-commit candidate\n",
            1,
        )
        token_expansion = original.replace(
            "          CPA_COMPAT_VERIFY_REMOTE: '1'\n",
            "          CPA_COMPAT_VERIFY_REMOTE: '1'\n"
            "          UNREVIEWED_TOKEN: ${{ github.token }}\n",
            1,
        )
        git_tag = original.replace(
            "        run: ./scripts/round6-candidate-artifacts.sh\n",
            "        run: git tag -f v0.15 HEAD\n",
            1,
        )
        for workflow in (release_action, token_expansion, git_tag):
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError,
                "reviewed steps|github.token|repository token|exact reviewed text|tags or releases",
            ):
                validate_candidate_workflow(workflow, Path("candidate.yml"))

    def test_ci_workflow_rejects_checked_out_repository_token_exposure(self):
        source = Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml"
        original = source.read_text(encoding="utf-8")
        validate_ci_workflow(original, source)
        mutations = (
            original.replace(
                '          CPA_COMPAT_VERIFY_REMOTE: "1"\n',
                '          CPA_COMPAT_VERIFY_REMOTE: "1"\n'
                '          GITHUB_TOKEN: ${{ github.token }}\n',
                1,
            ),
            original.replace(
                '          CPA_COMPAT_VERIFY_REMOTE: "1"\n',
                '          CPA_COMPAT_VERIFY_REMOTE: "1"\n'
                "          GH_TOKEN: ${{ github['token'] }}\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "github.token|repository token"):
                validate_ci_workflow(workflow, source)

    def test_ci_workflow_keeps_round8_counted_mock_in_an_isolated_historical_step(self):
        source = Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml"
        original = source.read_text(encoding="utf-8")
        block = (
            "      - name: Historical Round 8 counted-Mock regression\n"
            "        run: make round8-counted-mock-historical-regression\n"
        )
        mutations = (
            original.replace(block, "", 1),
            original.replace(
                "        run: make round8-counted-mock-historical-regression\n",
                "        run: make round6-module-verify\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "historical Round 8 counted-Mock"):
                validate_ci_workflow(workflow, source)

    def test_ci_workflow_requires_exact_remote_cpa_verification_step(self):
        source = Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml"
        original = source.read_text(encoding="utf-8")
        mutations = (
            original.replace(
                '          CPA_COMPAT_PROFILE: "primary"\n',
                '          CPA_COMPAT_PROFILE: "all"\n',
                1,
            ),
            original.replace(
                '          CPA_COMPAT_VERIFY_REMOTE: "1"\n',
                '          CPA_COMPAT_VERIFY_REMOTE: "0"\n',
                1,
            ),
            original.replace(
                '          CPA_COMPAT_VERIFY_REMOTE: "1"\n',
                '          CPA_LATEST_VERIFY_REMOTE: "1"\n',
                1,
            ),
            original.replace('          CPA_COMPAT_VERIFY_REMOTE: "1"\n', "", 1),
            original.replace(
                '          CPA_COMPAT_REQUIRE_LATEST: "1"\n',
                '          CPA_COMPAT_REQUIRE_LATEST: "0"\n',
                1,
            ),
            original.replace(
                '          CPA_COMPAT_REQUIRE_LATEST: "1"\n',
                '          CPA_LATEST_REQUIRED: "1"\n',
                1,
            ),
            original.replace('          CPA_COMPAT_REQUIRE_LATEST: "1"\n', "", 1),
            original.replace(
                "        run: make cpa-latest-compat\n",
                "        run: true\n",
                1,
            ),
            original.replace(CPA_CURRENT_VERSION, CPA_ROUND8_VERSION, 1),
            original.replace(CPA_CURRENT_COMMIT, CPA_ROUND8_COMMIT, 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError,
                rf"{re.escape(CPA_CURRENT_VERSION)} primary profile|latest source API and SDK|remote verification|latest-release drift check|current CPA|historical Round 8 identity|must be a mapping|exact scalar",
            ):
                validate_ci_workflow(workflow, source)

    def test_ci_workflow_fuzz_artifact_requires_fuzz_failure_and_validated_collection(self):
        source = Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml"
        original = source.read_text(encoding="utf-8")
        validate_ci_workflow(original, source)
        mutations = (
            original.replace(
                "        if: ${{ failure() && steps.fuzz.outcome == 'failure' }}\n",
                "        if: ${{ failure() }}\n",
                1,
            ),
            original.replace(
                "        if: ${{ failure() && steps.fuzz.outcome == 'failure' && steps.collect_fuzz.outcome == 'success' }}\n",
                "        if: ${{ failure() && steps.fuzz.outcome == 'failure' }}\n",
                1,
            ),
            original.replace("      - id: fuzz\n", "      - id: fuzz_job\n", 1),
            original.replace("        id: collect_fuzz\n", "        id: collect_output\n", 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError,
                "fuzz failure artifact|exact scalar",
            ):
                validate_ci_workflow(workflow, source)

    def test_candidate_scripts_match_reviewed_contract_and_are_ci_reachable(self):
        root = Path(__file__).parent.parent
        for name in (
            "round6-candidate-artifacts.sh",
            "release-candidate-contract-test.sh",
        ):
            with self.subTest(name=name):
                source = root / "scripts" / name
                text = source.read_text(encoding="utf-8")
                validate_candidate_script(text, source)
                with self.assertRaisesRegex(ContractError, "exact reviewed"):
                    validate_candidate_script(text + "\n# bypass\n", source)
        _, inspected = audit(root, default_entrypoints(root))
        self.assertTrue(
            {
                "scripts/round6-candidate-artifacts.sh",
                "scripts/release-candidate-contract-test.sh",
                "scripts/reproducibility-test.sh",
                "scripts/verify-frozen-evaluation-v10-tree.sh",
                "scripts/verify-external-release-attestation.sh",
                "scripts/verify-external-release-attestation-test.sh",
            }.issubset(inspected)
        )

    def test_formal_release_workflow_full_contract_passes(self):
        validate_formal_release_workflow(
            self.formal_release_workflow(), Path("release.yml")
        )

    def test_formal_release_remote_cpa_verification_cannot_be_disabled_or_renamed(self):
        original = self.formal_release_workflow()
        mutations = (
            (
                original.replace(
                    "          CPA_COMPAT_VERIFY_REMOTE: '1'\n",
                    "          CPA_COMPAT_VERIFY_REMOTE: '0'\n",
                    1,
                ),
                "remote CPA verification",
            ),
            (
                original.replace(
                    "          CPA_COMPAT_VERIFY_REMOTE: '1'\n",
                    "          CPA_LATEST_VERIFY_REMOTE: '1'\n",
                    1,
                ),
                "remote CPA verification",
            ),
            (
                original.replace("          CPA_COMPAT_VERIFY_REMOTE: '1'\n", "", 1),
                "must be a mapping",
            ),
        )
        for workflow, error_pattern in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, error_pattern):
                validate_formal_release_workflow(workflow, Path("release.yml"))

    def test_formal_release_read_build_and_write_publish_are_separated(self):
        original = self.formal_release_workflow()
        mutations = (
            original.replace("      actions: read\n", "", 1),
            original.replace("      contents: read\n", "      contents: write\n", 1),
            original.replace(
                "      ROUND6_SAFE_SPARSE_BUILD: '1'\n",
                "      ROUND6_SAFE_SPARSE_BUILD: '0'\n",
                1,
            ),
            original.replace("          BASH_ENV: ''\n", "          BASH_ENV: /tmp/attacker\n", 1),
            original.replace(
                "      - name: Download exact verified release artifact\n",
                "      - name: Checkout in write job\n"
                "        uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n"
                "      - name: Download exact verified release artifact\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError,
                "actions|exact scalar|four reviewed steps|contents|verifier environment|sparse-build",
            ):
                validate_formal_release_workflow(workflow, Path("release.yml"))

    def test_formal_release_draft_flags_and_attested_assets_are_locked(self):
        original = self.formal_release_workflow()
        mutations = (
            original.replace("          draft: true\n", "          draft: false\n", 1),
            original.replace("          make_latest: false\n", "          make_latest: true\n", 1),
            original.replace(
                "            dist/formal-release-attestation.json.sha256\n",
                "",
                1,
            ),
            original.replace(
                '          cmp -s "$ROUND6_CANDIDATE_SO" dist/cyber-abuse-guard-v0.15.so\n',
                "",
                1,
            ),
            original.replace(
                '            ./scripts/verify-external-release-attestation.sh "$attestation"\n',
                "",
                1,
            ),
            original.replace("            !/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*\n", "", 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError,
                "exact scalar|artifact transfer|exact reviewed text|sparse checkout",
            ):
                validate_formal_release_workflow(workflow, Path("release.yml"))

    def test_formal_release_no_checkout_admission_is_required_before_build(self):
        original = self.formal_release_workflow()
        mutations = (
            original.replace("    needs: admission\n", "", 1),
            original.replace(
                '          [[ "$(jq -r \'.object.sha\' <<<"$main_ref")" == "$DISPATCH_SHA" ]]\n',
                "",
                1,
            ),
            original.replace(
                '              .commit == $commit and .tree == $tree and\n',
                '              .tree == $tree and\n',
                1,
            ),
            original.replace(
                "      - name: Admit exact main-tip tag and attested Round6 candidate before checkout\n",
                "      - name: Checkout unadmitted repository code\n"
                "        uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n"
                "      - name: Admit exact main-tip tag and attested Round6 candidate before checkout\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError, "admission|exact reviewed text|exact scalar|no-checkout|keys/order"
            ):
                validate_formal_release_workflow(workflow, Path("release.yml"))

    def test_formal_release_consumed_sparse_boundary_is_locked(self):
        original = self.formal_release_workflow()
        workflow = original.replace(
            "            !/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*\n", "", 1
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "sparse checkout"):
            validate_formal_release_workflow(workflow, Path("release.yml"))

    def test_formal_operations_cannot_use_candidate_tag_bypass(self):
        root = Path(__file__).parent.parent
        validate_release_mode_contracts(root)
        metadata_source = root / "scripts/release-build-metadata.sh"
        metadata = metadata_source.read_text(encoding="utf-8")
        validate_release_build_metadata_script(metadata, metadata_source)
        metadata_mutations = (
            metadata.replace("schema_version: 4,", "schema_version: 3,", 1),
            metadata.replace('cc_command="$($go_bin env CC)"', 'cc_command="cc"', 1),
            metadata.replace(
                '[[ "$builder_image_digest" =~ ^sha256:[0-9a-f]{64}$ ]]',
                "true",
                1,
            ),
            metadata.replace("builder_image_digest: $builder_image_digest,", "", 1),
            metadata.replace(
                '[[ "$builder_reference" == "${builder_image}@${builder_image_digest}" ]]',
                "true",
                1,
            ),
            metadata.replace("builder_reference: $builder_reference,", "", 1),
            metadata.replace(
                'runner_environment="${RC_RUNNER_ENVIRONMENT:-NOT_PROVIDED}"',
                'runner_environment="github-hosted"',
                1,
            ),
            metadata.replace(
                '[[ "$runner_environment" == github-hosted ]]',
                "true",
                1,
            ),
            metadata.replace(
                "unobservable_runner_image='UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER'",
                "unobservable_runner_image='ubuntu24'",
                1,
            ),
            metadata.replace(
                "reproducible_runner_name='UNRECORDED_EPHEMERAL_GITHUB_HOSTED_RUNNER'",
                "reproducible_runner_name='GitHub Actions 42'",
                1,
            ),
            metadata.replace(
                '[[ "$runner_name" == "$reproducible_runner_name" ]]',
                "true",
                1,
            ),
            metadata.replace("runner_name: $runner_name,", "", 1),
            metadata.replace("runner_image_version: $runner_image_version", "", 1),
        )
        for mutation in metadata_mutations:
            self.assertNotEqual(mutation, metadata)
            reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
            with mock.patch(
                "round6_safe_gate_contract.RELEASE_BUILD_METADATA_SCRIPT_SHA256",
                reviewed_hash,
            ):
                with self.assertRaisesRegex(ContractError, "schema-4|schema 4"):
                    validate_release_build_metadata_script(mutation, metadata_source)
        for script_name in FORMAL_OPERATION_SCRIPTS:
            with self.subTest(script_name=script_name):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                fixture = Path(temporary.name)
                (fixture / "scripts").mkdir()
                names = (
                    "release-common.sh",
                ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256)
                for name in names:
                    text = (root / "scripts" / name).read_text(encoding="utf-8")
                    if name == script_name:
                        text = text.replace("release_assert_formal_build\n", "true\n", 1)
                    (fixture / "scripts" / name).write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(ContractError, "release_assert_formal_build"):
                    validate_release_mode_contracts(fixture)

    def test_rc_release_assets_are_cross_dispatch_reproducible(self):
        root = Path(__file__).parent.parent
        source = root / "scripts/round6-rc-artifacts.sh"
        original = source.read_text(encoding="utf-8")
        validate_rc_reproducible_release_asset_contract(original, source)
        mutations = (
            original.replace(
                "runner_name_reproducible='UNRECORDED_EPHEMERAL_GITHUB_HOSTED_RUNNER'",
                'runner_name_reproducible="${RC_RUNNER_NAME}"',
                1,
            ),
            original.replace(
                "workflow_run_reproducible='UNRECORDED_EPHEMERAL_GITHUB_ACTIONS_RUN'",
                'workflow_run_reproducible="$GITHUB_RUN_ID"',
                1,
            ),
            original.replace(
                "workflow_attempt_reproducible='UNRECORDED_EPHEMERAL_GITHUB_ACTIONS_ATTEMPT'",
                'workflow_attempt_reproducible="$GITHUB_RUN_ATTEMPT"',
                1,
            ),
            original.replace("'summary_schema=1' \\\n", "'summary_schema=2' \\\n", 1),
            original.replace("'dynamic_stdout_included=false' \\\n", "'dynamic_stdout_included=true' \\\n", 1),
            original.replace(
                'cmp -s "$summary_input" "$expected_summary" || \\\n',
                "true || \\\n",
                1,
            ),
            original.replace(
                '--arg run_id "$workflow_run_reproducible" \\\n',
                '--argjson run_id "$GITHUB_RUN_ID" \\\n',
                1,
            ),
            original.replace(
                '--arg run_attempt "$workflow_attempt_reproducible" \\\n',
                '--argjson run_attempt "$GITHUB_RUN_ATTEMPT" \\\n',
                1,
            ),
        )
        for mutation in mutations:
            self.assertNotEqual(mutation, original)
            with self.assertRaisesRegex(
                ContractError,
                "canonical|stable ephemeral|serialize|dynamic workflow identity",
            ):
                validate_rc_reproducible_release_asset_contract(mutation, source)

    def test_formal_release_document_override_environment_rejection_is_locked(self):
        root = Path(__file__).parent.parent
        original = (root / "scripts/formal-release.sh").read_text(encoding="utf-8")
        override_block = (
            "for override in \\\n"
            "  RELEASE_DOC_ROOT \\\n"
            "  RELEASE_DOC_FIXTURE_MODE \\\n"
            "  CURRENT_RELEASE_VERSION \\\n"
            "  CURRENT_RULESET_SHA256 \\\n"
            "  CURRENT_CLASSIFIER_POLICY_VERSION \\\n"
            "  CURRENT_CLASSIFIER_POLICY_SHA256; do\n"
            '  if [[ -n "${!override+x}" ]]; then\n'
            '    release_die "formal release forbids release document override environment: '
            '$override"\n'
            "  fi\n"
            "done\n"
        )
        document_gate = '"$root/scripts/release-doc-consistency.sh"\n'
        mutations = (
            original.replace("  RELEASE_DOC_ROOT \\\n", "", 1),
            original.replace('${!override+x}', '${!override}', 1),
            original.replace(
                '    release_die "formal release forbids release document override environment: '
                '$override"\n',
                "    true\n",
                1,
            ),
            original.replace(
                override_block + document_gate,
                document_gate + override_block,
                1,
            ),
        )
        names = (
            "release-common.sh",
        ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256)
        for mutation in mutations:
            self.assertNotEqual(mutation, original)
            with self.subTest(mutation=mutation):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                fixture = Path(temporary.name)
                (fixture / "scripts").mkdir()
                for name in names:
                    text = (root / "scripts" / name).read_text(encoding="utf-8")
                    if name == "formal-release.sh":
                        text = mutation
                    (fixture / "scripts" / name).write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(ContractError, "document override environment"):
                    validate_release_mode_contracts(fixture)

    def test_public_jailbreak_audit_report_packaging_is_locked(self):
        root = Path(__file__).parent.parent
        package_original = (root / "scripts/package-release.sh").read_text(
            encoding="utf-8"
        )
        verify_original = (root / "scripts/verify-release.sh").read_text(
            encoding="utf-8"
        )
        source_marker = (
            '  "$root/docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md" \\\n'
        )
        first = package_original.index(source_marker)
        second = package_original.index(source_marker, first + len(source_marker))
        mutations = (
            (
                "package-release.sh",
                package_original[:first]
                + package_original[first + len(source_marker) :],
            ),
            (
                "package-release.sh",
                package_original[:second]
                + package_original[second + len(source_marker) :],
            ),
            (
                "verify-release.sh",
                verify_original.replace(
                    "docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md\n",
                    "",
                    1,
                ),
            ),
        )
        names = (
            "release-common.sh",
        ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256)
        for changed_name, mutation in mutations:
            with self.subTest(changed_name=changed_name):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                fixture = Path(temporary.name)
                (fixture / "scripts").mkdir()
                for name in names:
                    text = (root / "scripts" / name).read_text(encoding="utf-8")
                    if name == changed_name:
                        text = mutation
                    (fixture / "scripts" / name).write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(ContractError, "public jailbreak audit report"):
                    validate_release_mode_contracts(fixture)

    def test_release_common_formal_assertion_rejects_candidate_mode(self):
        root = Path(__file__).parent.parent
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture = Path(temporary.name)
        (fixture / "scripts").mkdir()
        for name in (
            "release-common.sh",
        ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256):
            text = (root / "scripts" / name).read_text(encoding="utf-8")
            if name == "release-common.sh":
                text = text.replace(
                    '[[ "$RELEASE_BUILD_KIND" == formal ]]',
                    '[[ "$RELEASE_BUILD_KIND" == candidate ]]',
                    1,
                )
            (fixture / "scripts" / name).write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "reject candidate"):
            validate_release_mode_contracts(fixture)

    def test_release_common_clears_inherited_git_repository_environment(self):
        root = Path(__file__).parent.parent
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture = Path(temporary.name)
        (fixture / "scripts").mkdir()
        names = (
            "release-common.sh",
        ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256)
        for name in names:
            text = (root / "scripts" / name).read_text(encoding="utf-8")
            if name == "release-common.sh":
                text = text.replace(
                    "unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR \\\n"
                    "  GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE\n",
                    "",
                    1,
                )
            (fixture / "scripts" / name).write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "repository-routing"):
            validate_release_mode_contracts(fixture)

    def test_external_attestation_verifier_and_contract_are_locked(self):
        root = Path(__file__).parent.parent
        for changed_name in EXTERNAL_ATTESTATION_SCRIPT_SHA256:
            with self.subTest(changed_name=changed_name):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                fixture = Path(temporary.name)
                (fixture / "scripts").mkdir()
                names = (
                    "release-common.sh",
                ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256)
                for name in names:
                    text = (root / "scripts" / name).read_text(encoding="utf-8")
                    if name == changed_name:
                        text += "\n# bypass\n"
                    (fixture / "scripts" / name).write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(
                    ContractError, "external release attestation script differs"
                ):
                    validate_release_mode_contracts(fixture)

    def test_round8_host_runner_scripts_are_mutation_locked(self):
        root = Path(__file__).parent.parent
        for changed_relative in ROUND8_HOST_REVIEWED_SCRIPT_SHA256:
            with self.subTest(changed_relative=changed_relative):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                fixture = Path(temporary.name)
                (fixture / "scripts").mkdir()
                names = (
                    "release-common.sh",
                ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256)
                for name in names:
                    text = (root / "scripts" / name).read_text(encoding="utf-8")
                    (fixture / "scripts" / name).write_text(text, encoding="utf-8")
                for relative in ROUND8_HOST_REVIEWED_SCRIPT_SHA256:
                    text = (root / relative).read_text(encoding="utf-8")
                    if relative == changed_relative:
                        text += "\n# mutation\n"
                    destination = fixture / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(
                    ContractError, "Round8 Host runner script differs"
                ):
                    validate_release_mode_contracts(fixture)

    def test_round9_active_workflows_reject_retired_host_sidecar_reintroduction(self):
        root = Path(__file__).parent.parent
        validators = (
            (
                root / ".github/workflows/round9-gate.yml",
                validate_round9_gate_workflow,
                "ROUND9_GATE_WORKFLOW_SHA256",
            ),
            (
                root / ".github/workflows/round9-host-validation.yml",
                validate_round9_host_workflow,
                "ROUND9_HOST_WORKFLOW_SHA256",
            ),
            (
                root / ".github/workflows/round9-release-rc.yml",
                validate_round9_rc_workflow,
                "ROUND9_RC_WORKFLOW_SHA256",
            ),
        )
        for path, validator, hash_name in validators:
            with self.subTest(workflow=path.name):
                mutation = path.read_text(encoding="utf-8") + "\n# round9-host-evidence.json\n"
                reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
                with mock.patch(f"round6_safe_gate_contract.{hash_name}", reviewed_hash):
                    with self.assertRaisesRegex(ContractError, "retired|Host sidecar|forbidden"):
                        validator(mutation, path)

    def test_release_evidence_uses_exact_immutable_attestation_snapshot_contract(self):
        root = Path(__file__).parent.parent
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture = Path(temporary.name)
        (fixture / "scripts").mkdir()
        names = (
            "release-common.sh",
        ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256)
        for name in names:
            text = (root / "scripts" / name).read_text(encoding="utf-8")
            if name == "generate-release-evidence.sh":
                text = text.replace(
                    'cp --no-dereference -- "$external_attestation_input" \\\n',
                    'true # removed immutable attestation snapshot copy\n',
                    1,
                )
            (fixture / "scripts" / name).write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "immutable attestation snapshot"):
            validate_release_mode_contracts(fixture)

    def test_release_promotion_full_contract_passes(self):
        validate_release_promote_workflow(
            self.release_promote_workflow(), Path("release-promote.yml")
        )

    def test_release_promotion_remains_manual_no_checkout_and_write_isolated(self):
        original = self.release_promote_workflow()
        mutations = (
            original.replace("  workflow_dispatch:\n", "  push:\n", 1),
            original.replace("    environment: formal-release-promotion\n", "", 1),
            original.replace("      contents: read\n", "      contents: write\n", 1),
            original.replace(
                "      - name: Reverify immutable asset set and publish the same draft\n",
                "      - name: Checkout attacker source\n"
                "        uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n"
                "      - name: Reverify immutable asset set and publish the same draft\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError,
                "workflow_dispatch|environment|write|read|exact scalar|one reviewed step",
            ):
                validate_release_promote_workflow(workflow, Path("release-promote.yml"))

    def test_release_promotion_ref_fingerprint_and_patch_are_locked(self):
        original = self.release_promote_workflow()
        protected_lines = (
            '          [[ "$DISPATCH_REF" == refs/tags/v0.15 ]]\n',
            '          [[ "$actual_fingerprint" == "$EXPECTED_ASSET_FINGERPRINT" ]]\n',
            '          [[ "$actual_metadata_fingerprint" == "$EXPECTED_METADATA_FINGERPRINT" ]]\n',
            "          promoted=\"$(gh api --method PATCH \\\n",
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed text"):
                    validate_release_promote_workflow(
                        workflow, Path("release-promote.yml")
                    )

    def blocked_workflow(self, trigger: str = "workflow_dispatch", latest: str = "false") -> str:
        source = Path(__file__).parent.parent / ".github/workflows/attested-prerelease.yml"
        text = source.read_text(encoding="utf-8")
        if trigger != "workflow_dispatch":
            text = text.replace("  workflow_dispatch:\n", f"  {trigger}:\n", 1)
        if latest != "false":
            text = text.replace("--latest=false", f"--latest={latest}", 1)
        return text

    def test_blocked_prerelease_full_contract_passes(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name) / "attested-prerelease.yml"
        validate_blocked_prerelease_workflow(self.blocked_workflow(), source)

    def test_blocked_prerelease_consumed_sparse_boundary_is_locked(self):
        original = self.blocked_workflow()
        workflow = original.replace(
            "            !/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*\n", "", 1
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "sparse"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_automatic_trigger_fails(self):
        with self.assertRaisesRegex(ContractError, "manual-only"):
            validate_blocked_prerelease_workflow(
                self.blocked_workflow(trigger="push"), Path("round6-prerelease.yml")
            )

    def test_workflow_dispatch_rejects_more_than_ten_inputs(self):
        original = self.blocked_workflow()
        extra_inputs = "".join(
            f"      extra_input_{index:02d}:\n"
            f"        description: Repository-reviewed input cap regression {index:02d}\n"
            "        required: true\n"
            "        type: string\n"
            for index in range(1, 18)
        )
        workflow = original.replace(
            "      authorize_blocked_prerelease:\n",
            extra_inputs + "      authorize_blocked_prerelease:\n",
            1,
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "repository-reviewed limit of 10"):
            validate_blocked_prerelease_workflow(
                workflow, Path("round6-prerelease.yml")
            )

    def test_blocked_prerelease_latest_true_fails(self):
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(
                self.blocked_workflow(latest="true"), Path("round6-prerelease.yml")
            )

    def test_blocked_prerelease_missing_expected_tree_fails(self):
        workflow = self.blocked_workflow().replace(
            "      expected_tree:\n", "      removed_expected_tree:\n", 1
        )
        with self.assertRaisesRegex(ContractError, "expected_tree"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_ci_run_id_fails(self):
        workflow = self.blocked_workflow().replace(
            "      ci_run_id:\n", "      removed_ci_run_id:\n", 1
        )
        with self.assertRaisesRegex(ContractError, "ci_run_id"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_candidate_run_id_fails(self):
        workflow = self.blocked_workflow().replace(
            "      candidate_run_id:\n", "      removed_candidate_run_id:\n", 1
        )
        with self.assertRaisesRegex(ContractError, "candidate_run_id"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_expected_so_sha256_fails(self):
        workflow = self.blocked_workflow().replace(
            "      expected_so_sha256:\n", "      removed_expected_so_sha256:\n", 1
        )
        with self.assertRaisesRegex(ContractError, "expected_so_sha256"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_expected_store_zip_sha256_fails(self):
        workflow = self.blocked_workflow().replace(
            "      expected_store_zip_sha256:\n",
            "      removed_expected_store_zip_sha256:\n",
            1,
        )
        with self.assertRaisesRegex(ContractError, "expected_store_zip_sha256"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_requires_consumed_independent_evaluation(self):
        original = self.blocked_workflow()
        for field_name in (
            "independent_evaluation_validation",
            "independent_evaluation_id",
            "independent_evaluation_sha256",
        ):
            with self.subTest(field_name=field_name):
                workflow = original.replace(
                    f'              "{field_name}"',
                    f'              "removed_{field_name}"',
                    1,
                )
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed"):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_evaluation_pass_id_and_hash_gates_are_locked(self):
        original = self.blocked_workflow()
        protected_lines = (
            '            .independent_evaluation_validation == "PASS" and\n',
            '            (.independent_evaluation_id | test("^evaluation-v(1[1-9]|[2-9][0-9]|[1-9][0-9]{2,})$")) and\n',
            '            (.independent_evaluation_sha256 | test("^[0-9a-f]{64}$"))\n',
            "      fromJSON(inputs.external_attestations_json).independent_evaluation_validation == 'PASS' &&\n",
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(
                    ContractError, "exact reviewed|missing explicit gate"
                ):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

        leading_zero_bypass = original.replace(
            "^evaluation-v(1[1-9]|[2-9][0-9]|[1-9][0-9]{2,})$",
            "^evaluation-v([0-9]+)$",
            1,
        )
        self.assertNotEqual(leading_zero_bypass, original)
        with self.assertRaisesRegex(ContractError, "exact reviewed"):
            validate_blocked_prerelease_workflow(
                leading_zero_bypass, Path("round6-prerelease.yml")
            )

    def test_blocked_prerelease_candidate_run_identity_is_locked(self):
        original = self.blocked_workflow()
        protected_lines = (
            '             .name == "Candidate build - NOT A RELEASE" and\n',
            '             .path == ".github/workflows/candidate.yml" and\n',
            '             .event == "workflow_dispatch" and\n'
            '             .head_sha == $expected_commit and\n',
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed"):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_missing_host_inputs_fail(self):
        original = self.blocked_workflow()
        missing_input = original.replace(
            "      external_attestations_json:\n",
            "      removed_external_attestations_json:\n",
            1,
        )
        self.assertNotEqual(missing_input, original)
        with self.assertRaisesRegex(ContractError, "external_attestations_json"):
            validate_blocked_prerelease_workflow(
                missing_input, Path("round6-prerelease.yml")
            )
        for field_name in ("host_validation", "host_evidence_sha256"):
            with self.subTest(field_name=field_name):
                workflow = original.replace(
                    f'              "{field_name}"',
                    f'              "removed_{field_name}"',
                    1,
                )
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed"):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_external_json_shape_and_types_are_locked(self):
        original = self.blocked_workflow()
        mutations = (
            original.replace(
                '            type == "object" and\n',
                '            type != "object" and\n',
                1,
            ),
            original.replace(
                '            (keys == [\n',
                '            (keys | length >= 7) and ([\n',
                1,
            ),
            original.replace(
                '            ([.[] | type] | all(. == "string")) and\n',
                '            true and\n',
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "exact reviewed"):
                validate_blocked_prerelease_workflow(
                    workflow, Path("round6-prerelease.yml")
                )

    def test_blocked_prerelease_rejects_legacy_host_blockers(self):
        original = self.blocked_workflow()
        legacy_input = original.replace(
            "      external_attestations_json:\n",
            "      host_v7282_validation:\n"
            "        description: Legacy Host blocker must not return\n"
            "        required: true\n"
            "        type: string\n"
            "      external_attestations_json:\n",
            1,
        )
        legacy_gate = original.replace(
            "      fromJSON(inputs.external_attestations_json).host_validation == 'PASS' &&\n",
            "      fromJSON(inputs.external_attestations_json).host_validation == 'PASS' &&\n"
            "      fromJSON(inputs.external_attestations_json).host_v7282_validation == 'PASS' &&\n",
            1,
        )
        for workflow in (legacy_input, legacy_gate):
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "keys/order changed|explicit gate"):
                validate_blocked_prerelease_workflow(
                    workflow, Path("round6-prerelease.yml")
                )

    def test_blocked_prerelease_missing_actions_read_fails(self):
        workflow = self.blocked_workflow().replace("  actions: read\n", "")
        with self.assertRaisesRegex(ContractError, "actions: read"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_protected_environment_fails(self):
        workflow = self.blocked_workflow().replace(
            "    environment: round6-independent-audit\n", ""
        )
        with self.assertRaisesRegex(ContractError, "protected environment"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_ci_conclusion_fails(self):
        workflow = self.blocked_workflow().replace(
            '             .conclusion == "success" and\n',
            '             .conclusion != "success" and\n',
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_admission_comment_spoof_fails(self):
        workflow = self.blocked_workflow().replace(
            '            .host_validation == "PASS" and\n',
            '            # .host_validation == "PASS" and\n            true and\n',
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_identity_env_spoof_fails(self):
        original = self.blocked_workflow()
        cases = (
            ("DISPATCH_REF", "${{ github.ref }}", "refs/heads/main"),
            ("DISPATCH_SHA", "${{ github.sha }}", "0000000000000000000000000000000000000000"),
            ("WORKFLOW_REF", "${{ github.workflow_ref }}", "owner/repo/.github/workflows/attested-prerelease.yml@refs/heads/main"),
            ("WORKFLOW_SHA", "${{ github.workflow_sha }}", "0000000000000000000000000000000000000000"),
        )
        for name, expected, spoofed in cases:
            with self.subTest(name=name):
                workflow = original.replace(
                    f"          {name}: {expected}\n",
                    f"          {name}: {spoofed}\n",
                    1,
                )
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed"):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_identity_command_spoof_fails(self):
        original = self.blocked_workflow()
        commands = (
            '[[ "$DISPATCH_REF" == "refs/tags/$TAG" ]]',
            '[[ "$DISPATCH_SHA" == "$EXPECTED_COMMIT" ]]',
            '[[ "$WORKFLOW_SHA" == "$EXPECTED_COMMIT" ]]',
            '[[ "$WORKFLOW_REF" == "${GITHUB_REPOSITORY}/.github/workflows/attested-prerelease.yml@refs/tags/$TAG" ]]',
        )
        for command in commands:
            with self.subTest(command=command):
                workflow = original.replace(
                    f"          {command}\n",
                    "          true\n",
                    1,
                )
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed"):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_if_expression_spoof_fails(self):
        workflow = self.blocked_workflow().replace(
            "    if: >-\n      fromJSON(inputs.external_attestations_json).host_validation == 'PASS' &&\n      fromJSON(inputs.external_attestations_json).independent_audit_validation == 'PASS' &&\n      fromJSON(inputs.external_attestations_json).independent_evaluation_validation == 'PASS' &&\n      inputs.authorize_blocked_prerelease == true\n",
            "    if: ${{ true }}\n"
            "    # fromJSON(inputs.external_attestations_json).host_validation == 'PASS' &&\n"
            "    # fromJSON(inputs.external_attestations_json).independent_audit_validation == 'PASS' && fromJSON(inputs.external_attestations_json).independent_evaluation_validation == 'PASS' &&\n"
            "    # inputs.authorize_blocked_prerelease == true\n",
        )
        with self.assertRaisesRegex(ContractError, "missing explicit gate"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_host_gate_fails(self):
        original = self.blocked_workflow()
        workflow = original.replace(
            "      fromJSON(inputs.external_attestations_json).host_validation == 'PASS' &&\n",
            "",
            1,
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "missing explicit gate"):
            validate_blocked_prerelease_workflow(
                workflow, Path("round6-prerelease.yml")
            )

    def test_blocked_prerelease_missing_remote_tag_recheck_fails(self):
        workflow = self.blocked_workflow().replace(
            "          tag_ref=\"$(/usr/bin/gh api --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG\")\"\n",
            "",
        )
        self.assertNotEqual(workflow, self.blocked_workflow())
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_metadata_identity_fails(self):
        workflow = self.blocked_workflow().replace(
            ".commit == $commit and .tree == $tree",
            ".commit != $commit or .tree != $tree",
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_identity_comment_spoof_fails(self):
        workflow = self.blocked_workflow().replace(
            "          tag_ref=\"$(/usr/bin/gh api --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG\")\"\n",
            "          # tag_ref=\"$(/usr/bin/gh api --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG\")\"\n",
        )
        self.assertNotEqual(workflow, self.blocked_workflow())
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_identity_or_true_fails(self):
        workflow = self.blocked_workflow().replace(
            '          [[ "$(/usr/bin/jq -r \'.ref\' <<<"$tag_ref")" == "refs/tags/$TAG" ]]\n',
            '          [[ "$(/usr/bin/jq -r \'.ref\' <<<"$tag_ref")" == "refs/tags/$TAG" ]] || true\n',
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_identity_if_false_fails(self):
        workflow = self.blocked_workflow().replace(
            "          tag_ref=\"$(/usr/bin/gh api --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG\")\"\n",
            "          if false; then\n"
            "          tag_ref=\"$(/usr/bin/gh api --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG\")\"\n",
        ).replace(
            '          [[ "$(/usr/bin/jq -r \'.ref\' <<<"$tag_ref")" == "refs/tags/$TAG" ]]\n',
            '          [[ "$(/usr/bin/jq -r \'.ref\' <<<"$tag_ref")" == "refs/tags/$TAG" ]]\n          fi\n',
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_identity_semicolon_true_fails(self):
        workflow = self.blocked_workflow().replace(
            "            dist/build-metadata.json >/dev/null\n",
            "            dist/build-metadata.json >/dev/null; true\n",
            1,
        )
        self.assertNotEqual(workflow, self.blocked_workflow())
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_final_artifact_hash_or_true_fails(self):
        workflow = self.blocked_workflow().replace(
            '          [[ "$actual_so_sha256" == "$EXPECTED_SO_SHA256" ]]\n',
            '          [[ "$actual_so_sha256" == "$EXPECTED_SO_SHA256" ]] || true\n',
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_release_action_must_be_last(self):
        workflow = self.blocked_workflow() + """      - name: Mutate release afterward
        run: gh release edit "$TAG" --latest
"""
        with self.assertRaisesRegex(ContractError, "exactly four reviewed steps"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_existing_draft_extra_asset_guard_is_frozen(self):
        original = self.blocked_workflow()
        expected_builder = '          expected_assets_json="$(/usr/bin/jq -cn --args '
        guard = '            if ! /usr/bin/jq -e --argjson expected "$expected_assets_json" '
        final_exact_set = '          /usr/bin/jq -e --argjson expected "$expected_assets_json" '
        self.assertIn(expected_builder, original)
        self.assertIn(guard, original)
        self.assertIn(final_exact_set, original)
        self.assertIn('(($actual - $expected) | length == 0)', original)
        self.assertIn('(($actual | length) == ($actual | unique | length))', original)
        self.assertIn('(($actual | sort) == ($expected | sort))', original)
        self.assertNotIn('/usr/bin/comm -13', original)
        self.assertLess(
            original.index(expected_builder),
            original.index('            /usr/bin/gh release create "$TAG"'),
        )
        self.assertLess(
            original.index(guard),
            original.index('            /usr/bin/gh release edit "$TAG" \\\n'),
        )
        self.assertLess(
            original.index(guard),
            original.index('            /usr/bin/gh release upload "$TAG"'),
        )
        workflow = original.replace(guard, '            if /usr/bin/true; then # ', 1)
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_release_commands_pin_repository(self):
        original = self.blocked_workflow()
        repository_flag = '              --repo "$GITHUB_REPOSITORY" \\\n'
        self.assertEqual(original.count(repository_flag), 3)
        workflow = original.replace(repository_flag, "", 1)
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_duplicate_action_key_fails(self):
        workflow = self.blocked_workflow().replace(
            "            --draft \\\n", "            --draft \\\n            --draft \\\n", 1
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_missing_body_artifact_hash_fails(self):
        workflow = self.blocked_workflow().replace(
            '            "Candidate Linux amd64 SO SHA-256: $EXPECTED_SO_SHA256" \\\n',
            "            'Candidate Linux amd64 SO SHA-256: unavailable' \\\n",
            1,
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_attestation_identity_is_locked(self):
        original = self.blocked_workflow()
        protected_lines = (
            '              status: "HOST_AUDIT_AND_EVALUATION_PASS / FORMAL_RELEASE_BLOCKED",\n',
            "              candidate_run_id: ($candidate_run_id | tonumber),\n",
            "                store_zip_sha256: $store_zip_sha256\n",
            "                independent_audit_sha256: $independent_audit_sha256,\n",
            "                independent_evaluation_id: $independent_evaluation_id,\n",
            '                independent_evaluation_status: "CONSUMED / PASS",\n',
            "                independent_evaluation_sha256: $independent_evaluation_sha256\n",
            "                ref: $workflow_ref,\n",
            "            dist/round6-prerelease-attestation.json\n",
            "            dist/round6-prerelease-attestation.json.sha256\n",
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(
                    ContractError,
                    "exact reviewed text|attested artifact allowlist changed",
                ):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_missing_host_evidence_note_fails(self):
        original = self.blocked_workflow()
        workflow = original.replace(
            '            "CPA Host evidence SHA-256: $HOST_EVIDENCE_SHA256" \\\n',
            "",
            1,
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_verify_token_exposure_fails(self):
        workflow = self.blocked_workflow().replace(
            "          CPA_COMPAT_VERIFY_REMOTE: '1'\n",
            "          CPA_COMPAT_VERIFY_REMOTE: '1'\n          GITHUB_TOKEN: ${{ github.token }}\n",
            1,
        )
        with self.assertRaisesRegex(ContractError, "github.token|repository token"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_bracket_token_and_secret_exposure_fail(self):
        expressions = (
            "${{ github['token'] }}",
            "${{ secrets['WRITE_PAT'] }}",
            "${{ toJSON(github) }}",
            "${{ toJSON(secrets) }}",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                workflow = self.blocked_workflow().replace(
                    "          CPA_COMPAT_VERIFY_REMOTE: '1'\n",
                    "          CPA_COMPAT_VERIFY_REMOTE: '1'\n"
                    f"          UNREVIEWED_CONTEXT: {expression}\n",
                    1,
                )
                with self.assertRaisesRegex(
                    ContractError, "github.token|repository token|secrets context"
                ):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_semantic_step_control_bypasses_fail(self):
        mutations = (
            self.blocked_workflow().replace(
                "      - name: Fail closed unless every external gate and authorization is explicit\n",
                "      - name: Fail closed unless every external gate and authorization is explicit\n"
                "        if : false\n",
                1,
            ),
            self.blocked_workflow().replace(
                "      - name: Reverify source and artifact identity before transfer\n",
                "      - name: Reverify source and artifact identity before transfer\n"
                "        continue-on-error : true\n",
                1,
            ),
            self.blocked_workflow().replace(
                "      - name: Recheck immutable tag and create draft blocked prerelease\n",
                "      - name: Recheck immutable tag and create draft blocked prerelease\n"
                "        shell : bash {0}\n",
                1,
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaisesRegex(
                    ContractError, "keys/order changed|override the reviewed step shell"
                ):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_spaced_env_and_trigger_bypasses_fail(self):
        mutations = (
            self.blocked_workflow().replace(
                "env:\n  GO_VERSION:",
                "env :\n  BASH_ENV : /tmp/attacker\n  GO_VERSION:",
                1,
            ),
            self.blocked_workflow().replace(
                "\npermissions:\n", "  push :\n\npermissions:\n", 1
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaisesRegex(
                    ContractError, "top-level env|manual-only|dangerous execution-context"
                ):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_extra_action_and_changed_action_sha_fail(self):
        marker = "      - name: Reverify source and artifact identity before transfer\n"
        extra_action = self.blocked_workflow().replace(
            marker,
            "      - name: Unreviewed external action\n"
            "        uses: attacker/example@0123456789abcdef0123456789abcdef01234567\n"
            + marker,
            1,
        )
        changed_sha = self.blocked_workflow().replace(
            "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
            "actions/setup-go@0123456789abcdef0123456789abcdef01234567",
            1,
        )
        for workflow in (extra_action, changed_sha):
            with self.assertRaisesRegex(
                ContractError, "exactly eleven|exact scalar|dangerous execution-context"
            ):
                validate_blocked_prerelease_workflow(
                    workflow, Path("round6-prerelease.yml")
                )

    def test_blocked_prerelease_pull_request_ci_run_fails(self):
        workflow = self.blocked_workflow().replace(
            '             .event == "push" and\n',
            '             .event == "pull_request" and\n',
            1,
        )
        with self.assertRaisesRegex(ContractError, "exact reviewed"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_persisted_checkout_credentials_fail(self):
        workflow = self.blocked_workflow().replace(
            "          persist-credentials: false\n",
            "          persist-credentials: true\n",
            1,
        )
        with self.assertRaisesRegex(ContractError, "disable persisted credentials"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_early_release_mutation_fails(self):
        commands = (
            "gh release create v0.1.2-dev.round6 --latest",
            "gh api -X PATCH repos/example/example/git/refs/tags/v0.1.2-dev.round6",
            "git push origin refs/tags/v0.1.2-dev.round6",
            "git tag -f v0.1.2-dev.round6 HEAD",
            "git update-ref refs/tags/v0.1.2-dev.round6 HEAD",
            "curl -X POST https://api.github.test/repos/example/example/releases",
            "curl --data '{}' https://api.github.test/repos/example/example/releases",
            "curl -F file=@candidate.so https://api.github.test/upload",
            "curl --upload-file candidate.so https://api.github.test/upload",
            "wget --post-data=tag=v0.1.2-dev.round6 https://api.github.test/releases",
            "/usr/bin/curl --data '{}' https://api.github.test/releases",
            "command curl --data '{}' https://api.github.test/releases",
            "env curl --data '{}' https://api.github.test/releases",
            "env -S 'curl --data {} https://api.github.test/releases'",
            "sudo env --split-string='git --no-pager tag v0.1.2-dev.round6'",
            "/usr/bin/time -f %E git --no-pager tag v0.1.2-dev.round6",
            "timeout --signal KILL 5s gh --hostname github.com api repos/example/example",
            "nice -n 10 nohup stdbuf -oL wget --post-data=x https://api.github.test/releases",
            "bash -lc 'curl --data x https://api.github.test/releases'",
            "eval 'git tag v0.1.2-dev.round6'",
            "xargs curl",
            "find . -exec curl --data x https://api.github.test/releases {} \\;",
            "python3.14 -I -c 'import requests'",
            "node --eval=\"fetch('https://api.github.test/releases')\"",
        )
        for command in commands:
            with self.subTest(command=command):
                reasons = [
                    mutating_command_reason(segment)
                    for logical_command in mutation_shell_commands(command)
                    for segment in shell_command_segments(logical_command)
                ]
                self.assertTrue(any(reasons), command)

    def test_mutation_parser_handles_multiline_quotes_heredocs_and_fail_closed(self):
        script = """jq -e '(.commit == $commit and
 .tree == $tree)' build-metadata.json
cat <<'BODY'
curl --data attacker-controlled-body https://api.github.test/releases
BODY
command /usr/bin/git --no-pager tag v0.1.2-dev.round6
"""
        reasons = [
            mutating_command_reason(segment)
            for logical_command in mutation_shell_commands(script)
            for segment in shell_command_segments(logical_command)
            if mutating_command_reason(segment)
        ]
        self.assertEqual(reasons, ["git tag"])
        self.assertEqual(
            mutation_shell_commands("jq -r .value <<<'{}'\necho safe"),
            ("jq -r .value <<<'{}'", "echo safe"),
        )
        for malformed in ("echo 'unterminated", "cat <<BODY\nmissing terminator"):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(ContractError, "unterminated"):
                    mutation_shell_commands(malformed)

    def test_mutation_parser_rejects_array_execution_substitutions(self):
        commands = (
            'values=("$(gh release create v0.15)")',
            'values=(\n  "$(gh release create v0.15)"\n)',
            'values=(`gh release create v0.15`)',
            'values=( <(gh release create v0.15) )',
        )
        for command in commands:
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    ContractError, "shell array contains executable substitution"
                ):
                    mutation_shell_commands(command)

    def test_mutation_parser_even_trailing_backslashes_do_not_hide_command(self):
        script = "printf '%s' safe " + "\\\\" + "\ngh release create v0.15"
        reasons = [
            mutating_command_reason(segment)
            for command in mutation_shell_commands(script)
            for segment in shell_command_segments(command)
            if mutating_command_reason(segment)
        ]
        self.assertEqual(reasons, ["gh release"])

    def test_blocked_prerelease_github_env_bash_env_injection_fails(self):
        original = self.blocked_workflow()
        workflow = original.replace(
            "        run: make clean-tree-check\n",
            "        run: |\n"
            "          printf '%s\\n' 'BASH_ENV=/tmp/attacker' >> \"$GITHUB_ENV\"\n"
            "          make clean-tree-check\n",
            1,
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_required_verification_env_cannot_be_disabled(self):
        original = self.blocked_workflow()
        mutations = (
            original.replace("          CPA_COMPAT_VERIFY_REMOTE: '1'\n", "          CPA_COMPAT_VERIFY_REMOTE: '0'\n", 1),
            original.replace("          REQUIRE_DIST_ARTIFACTS: '1'\n", "          REQUIRE_DIST_ARTIFACTS: '0'\n", 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "exact reviewed mapping"):
                validate_blocked_prerelease_workflow(
                    workflow, Path("round6-prerelease.yml")
                )

    def test_blocked_prerelease_regression_step_cannot_be_noop(self):
        original = self.blocked_workflow()
        workflow = original.replace(
            "        run: |\n"
            "          make round6-format-check round6-git-diff-check round6-module-verify round6-regression round6-vet\n"
            "          go test ./internal/classifier -run '^TestClassifierPolicyIdentity$' -count=1\n",
            "        run: true\n",
            1,
        )
        self.assertNotEqual(workflow, original)
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_blocked_prerelease_clean_execution_env_is_exact(self):
        original = self.blocked_workflow()
        mutations = (
            original.replace("          BASH_ENV: ''\n", "", 1),
            original.replace("          BASH_ENV: ''\n", "          BASH_ENV: /tmp/attacker\n", 1),
            original.replace("          PATH: /usr/bin:/bin\n", "          PATH: /tmp/bin\n", 1),
            original.replace("          GIT_CONFIG_COUNT: '0'\n", "          GIT_CONFIG_COUNT: '1'\n", 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(
                ContractError, "exact reviewed mapping|dangerous execution-context"
            ):
                validate_blocked_prerelease_workflow(
                    workflow, Path("round6-prerelease.yml")
                )

    def test_blocked_prerelease_canonical_checksums_and_zip_identity_are_locked(self):
        original = self.blocked_workflow()
        protected_lines = (
            '          [[ "$actual_checksum_files" == "$expected_checksum_files" ]]\n',
            '          [[ "$(/usr/bin/sha256sum "$zip_so_file" | /usr/bin/awk \'{print $1}\')" == "$EXPECTED_SO_SHA256" ]]\n',
            '          [[ "$(/usr/bin/sha256sum "$zip_path" | /usr/bin/awk \'{print $1}\')" == "$EXPECTED_STORE_ZIP_SHA256" ]]\n',
            '          [[ "$zip_listing" == "$zip_so" ]]\n',
        )
        for protected_line in protected_lines:
            with self.subTest(protected_line=protected_line.strip()):
                workflow = original.replace(protected_line, "", 1)
                self.assertNotEqual(workflow, original)
                with self.assertRaisesRegex(ContractError, "exact reviewed text"):
                    validate_blocked_prerelease_workflow(
                        workflow, Path("round6-prerelease.yml")
                    )

    def test_blocked_prerelease_final_tag_peel_bypass_fails(self):
        workflow = self.blocked_workflow().replace(
            '          [[ "$(/usr/bin/jq -r \'.object.sha\' <<<"$tag_object")" == "$EXPECTED_COMMIT" ]]\n',
            '          [[ "$(/usr/bin/jq -r \'.object.sha\' <<<"$tag_object")" == "$EXPECTED_COMMIT" ]] || true\n',
            1,
        )
        self.assertNotEqual(workflow, self.blocked_workflow())
        with self.assertRaisesRegex(ContractError, "exact reviewed text"):
            validate_blocked_prerelease_workflow(workflow, Path("round6-prerelease.yml"))

    def test_active_rc_workflow_matches_reviewed_contract(self):
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        workflow = workflow_path.read_text(encoding="utf-8")
        validate_rc_release_workflow(workflow, workflow_path)

    def active_rc_host_zip_extractor(self) -> str:
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        workflow = workflow_path.read_text(encoding="utf-8")
        start_marker = '          python3 -B - "$archive" "$host_dir" <<\'PY\'\n'
        end_marker = '          PY\n          evidence="$host_dir/round8-host-evidence.json"'
        start = workflow.index(start_marker) + len(start_marker)
        end = workflow.index(end_marker, start)
        return textwrap.dedent(workflow[start:end])

    def run_active_rc_host_zip_extractor(
        self, entries: tuple[tuple[str, bytes, int], ...]
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        script = self.active_rc_host_zip_extractor()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        archive_path = root / "host.zip"
        destination = root / "output"
        destination.mkdir()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(
                archive_path, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                for name, payload, mode in entries:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = mode << 16
                    archive.writestr(info, payload)
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-",
                str(archive_path),
                str(destination),
            ],
            input=script,
            text=True,
            capture_output=True,
            check=False,
        )
        return result, destination

    def test_active_rc_host_zip_extractor_accepts_only_the_two_reviewed_files(self):
        regular = stat.S_IFREG | 0o600
        result, destination = self.run_active_rc_host_zip_extractor(
            (
                ("round8-host-evidence.json", b"{}", regular),
                (
                    "round8-host-evidence.json.sha256",
                    b"0" * 64 + b"  round8-host-evidence.json\n",
                    regular,
                ),
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((destination / "round8-host-evidence.json").read_bytes(), b"{}")
        self.assertEqual(
            (destination / "round8-host-evidence.json.sha256").read_bytes(),
            b"0" * 64 + b"  round8-host-evidence.json\n",
        )

    def test_active_rc_host_zip_extractor_rejects_unsafe_archives(self):
        regular = stat.S_IFREG | 0o600
        evidence = "round8-host-evidence.json"
        sidecar = "round8-host-evidence.json.sha256"
        cases = (
            (
                "entry_count",
                (
                    (evidence, b"{}", regular),
                    (sidecar, b"sidecar", regular),
                    ("unexpected.txt", b"extra", regular),
                ),
                "entry count exceeds",
            ),
            (
                "duplicate_name",
                ((evidence, b"one", regular), (evidence, b"two", regular)),
                "duplicate entry names",
            ),
            (
                "unexpected_name",
                ((evidence, b"{}", regular), ("unexpected.txt", b"x", regular)),
                "exactly the evidence and sidecar",
            ),
            (
                "path_traversal",
                ((evidence, b"{}", regular), ("../" + sidecar, b"x", regular)),
                "exactly the evidence and sidecar",
            ),
            (
                "directory",
                (
                    (evidence, b"{}", stat.S_IFDIR | 0o700),
                    (sidecar, b"x", regular),
                ),
                "directory or unsafe path",
            ),
            (
                "symlink",
                (
                    (evidence, b"target", stat.S_IFLNK | 0o777),
                    (sidecar, b"x", regular),
                ),
                "symbolic link",
            ),
            (
                "single_expanded_size",
                (
                    (evidence, b"x" * 16385, regular),
                    (sidecar, b"x", regular),
                ),
                "entry exceeds the expanded-size limit",
            ),
            (
                "total_expanded_size",
                (
                    (evidence, b"x" * 13000, regular),
                    (sidecar, b"y" * 13000, regular),
                ),
                "total expanded size exceeds",
            ),
        )
        for name, entries, error in cases:
            with self.subTest(case=name):
                result, _ = self.run_active_rc_host_zip_extractor(entries)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)

    def test_round8_host_workflow_matches_reviewed_contract(self):
        workflow_path = (
            Path(__file__).resolve().parent.parent
            / ".github/workflows/round8-host-validation.yml"
        )
        workflow = workflow_path.read_text(encoding="utf-8")
        validate_round8_host_workflow(workflow, workflow_path)

    def test_round9_workflows_match_reviewed_contract(self):
        root = Path(__file__).resolve().parent.parent
        validators = (
            ("round9-gate.yml", validate_round9_gate_workflow),
            ("round9-host-validation.yml", validate_round9_host_workflow),
            ("round9-release-rc.yml", validate_round9_rc_workflow),
        )
        for name, validator in validators:
            with self.subTest(workflow=name):
                path = root / ".github/workflows" / name
                validator(path.read_text(encoding="utf-8"), path)

    def test_round9_workflow_mutations_fail_closed(self):
        root = Path(__file__).resolve().parent.parent
        validators = (
            ("round9-gate.yml", validate_round9_gate_workflow),
            ("round9-host-validation.yml", validate_round9_host_workflow),
            ("round9-release-rc.yml", validate_round9_rc_workflow),
        )
        for name, validator in validators:
            with self.subTest(workflow=name):
                path = root / ".github/workflows" / name
                mutated = path.read_text(encoding="utf-8") + "\n# unreviewed mutation\n"
                with self.assertRaises(ContractError):
                    validator(mutated, path)

        gate_path = root / ".github/workflows/round9-gate.yml"
        gate = gate_path.read_text(encoding="utf-8")
        for mutation in (
            gate.replace("GOTOOLCHAIN: go1.26.4", "GOTOOLCHAIN: auto", 1),
            gate.replace("GOFLAGS: -mod=readonly", "GOFLAGS: -mod=mod", 1),
            gate.replace(
                "ROUND9_BENIGN_MANIFEST_SHA256: d33e4ff8954741a2fe9c24c0d34b239c649c7e0a6d31463cddba84dc6b6580b8",
                f"ROUND9_BENIGN_MANIFEST_SHA256: {'0' * 64}",
                1,
            ),
            gate.replace(
                "ROUND9_BENIGN_CASES_SHA256: 36d7f4dd635710f7ee81d02f9f62502c6276e554c80fc852f3d40acbfa70688d",
                f"ROUND9_BENIGN_CASES_SHA256: {'0' * 64}",
                1,
            ),
            gate.replace(
                "ROUND9_PAIRED_MANIFEST_SHA256: 29d84900edeec8fceceee9ccd2640571f1e962643931f388dcc842b058c6a2c2",
                f"ROUND9_PAIRED_MANIFEST_SHA256: {'0' * 64}",
                1,
            ),
            gate.replace(
                "ROUND9_PAIRED_CASES_SHA256: 2a30da8d4872029d9b070a7b8bd8fb72a132994a21975f64b49cd56ecf4b2b3d",
                f"ROUND9_PAIRED_CASES_SHA256: {'0' * 64}",
                1,
            ),
            gate.replace(
                "ROUND9_PAIRED_LABEL_AUDIT_SHA256: a2d34853f20ae1c0b18690a4f58f100fe0014c53232457d5084aa90407e2ab8f",
                f"ROUND9_PAIRED_LABEL_AUDIT_SHA256: {'0' * 64}",
                1,
            ),
            gate.replace(
                "!/testdata/round9-independent-benign-v1/**",
                "!/testdata/round9-independent-benign-v2/**",
                1,
            ),
        ):
            self.assertNotEqual(mutation, gate)
            reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
            with mock.patch(
                "round6_safe_gate_contract.ROUND9_GATE_WORKFLOW_SHA256",
                reviewed_hash,
            ):
                with self.assertRaises(ContractError):
                    validate_round9_gate_workflow(mutation, gate_path)

    def test_round9_rc_publication_block_and_candidate_contract_fail_closed(self):
        root = Path(__file__).resolve().parent.parent
        path = root / ".github/workflows/round9-release-rc.yml"
        original = path.read_text(encoding="utf-8")

        def replace_occurrence(
            text: str, old: str, new: str, occurrence: int
        ) -> str:
            start = 0
            for _ in range(occurrence):
                index = text.find(old, start)
                if index < 0:
                    return text
                start = index + len(old)
            return text[:index] + new + text[index + len(old) :]

        safe_gate_name = "      - name: Run exact Safe Gate after restricted checkout\n"
        mutations = (
            original.replace(
                "      ci_run_id: ${{ steps.admit.outputs.ci_run_id }}\n",
                "      already_public: true\n"
                "      ci_run_id: ${{ steps.admit.outputs.ci_run_id }}\n",
                1,
            ),
            original.replace(
                "      round9_gate_run:\n"
                "        description: Successful exact-main Round 9 policy-gate push run and attempt as RUN_ID:RUN_ATTEMPT\n"
                "        required: true\n"
                "        type: string\n",
                "",
                1,
            ),
            original.replace(
                '.event == "push" and .head_branch == "main" and',
                '.event == "workflow_dispatch" and .head_branch == "main" and',
                1,
            ),
            original.replace(
                "historical_repository='yujianwudi/cyber-abuse-guard'",
                'historical_repository="$GITHUB_REPOSITORY"',
                1,
            ),
            original.replace(
                'repos/${historical_repository}/git/ref/tags/v0.16-rc.2',
                'repos/${GITHUB_REPOSITORY}/git/ref/tags/v0.16-rc.2',
                1,
            ),
            original.replace(
                'main_ref="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main")"',
                'main_ref="$(gh api "repos/${historical_repository}/git/ref/heads/main")"',
                1,
            ),
            original.replace(
                'gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/releases?per_page=100"',
                'gh api --paginate --slurp "repos/${historical_repository}/releases?per_page=100"',
                1,
            ),
            original.replace(
                '.state == "disabled_manually"',
                '.state == "active"',
                1,
            ),
            original.replace(
                '[.[][] | select(.tag_name == $tag)] | length == 0',
                '[.[][] | select(.tag_name == $tag)] | length >= 0',
                1,
            ),
            original.replace(
                "ROUND9_NEW_PUBLIC_PRERELEASE_CREATION: "
                "BLOCKED_PENDING_EXACT_CANDIDATE_INDEPENDENT_AUDIT_GATE",
                "ROUND9_NEW_PUBLIC_PRERELEASE_CREATION: ALLOWED_BY_HOST_ONLY",
                1,
            ),
            original.replace(
                "8d0db0b3099298fe039b94e4c52a6987798a90d23b80de3ac13c3cb75cf622a2",
                "0" * 64,
                1,
            ),
            original.replace(
                "8d0db0b3099298fe039b94e4c52a6987798a90d23b80de3ac13c3cb75cf622a2",
                "0" * 64,
                2,
            ).replace(
                "0" * 64,
                "8d0db0b3099298fe039b94e4c52a6987798a90d23b80de3ac13c3cb75cf622a2",
                1,
            ),
            replace_occurrence(
                original,
                "207b539919a47c85bcf738677f0ccf5bbac9844f2d3f158696f518be4c4ba6c4",
                "0" * 64,
                1,
            ),
            replace_occurrence(
                original,
                "207b539919a47c85bcf738677f0ccf5bbac9844f2d3f158696f518be4c4ba6c4",
                "0" * 64,
                2,
            ),
            replace_occurrence(original, '== 53580 ]]', '== 53581 ]]', 1),
            replace_occurrence(original, '== 53580 ]]', '== 53581 ]]', 2),
            replace_occurrence(
                original,
                'Package)" == libyaml-0-2 ]]',
                'Package)" == libyaml-0-3 ]]',
                1,
            ),
            replace_occurrence(
                original,
                'Package)" == libyaml-0-2 ]]',
                'Package)" == libyaml-0-3 ]]',
                2,
            ),
            replace_occurrence(
                original,
                'Version)" == 0.2.5-1 ]]',
                'Version)" == 0.2.5-2 ]]',
                1,
            ),
            replace_occurrence(
                original,
                'Version)" == 0.2.5-1 ]]',
                'Version)" == 0.2.5-2 ]]',
                2,
            ),
            replace_occurrence(
                original,
                'Architecture)" == amd64 ]]',
                'Architecture)" == arm64 ]]',
                1,
            ),
            replace_occurrence(
                original,
                'Architecture)" == amd64 ]]',
                'Architecture)" == arm64 ]]',
                2,
            ),
            replace_occurrence(
                original, '          dpkg -i "$libyaml_package"\n', "", 1
            ),
            replace_occurrence(
                original, '          dpkg -i "$libyaml_package"\n', "", 2
            ),
            replace_occurrence(
                original,
                safe_gate_name,
                "      - name: Unreviewed step before Safe Gate\n"
                "        run: /usr/bin/true\n\n"
                + safe_gate_name,
                1,
            ),
            replace_occurrence(
                original,
                safe_gate_name,
                "      - name: Unreviewed step before Safe Gate\n"
                "        run: /usr/bin/true\n\n"
                + safe_gate_name,
                2,
            ),
            replace_occurrence(
                original,
                safe_gate_name,
                safe_gate_name + "        continue-on-error: ${{ true }}\n",
                1,
            ),
            replace_occurrence(
                original,
                safe_gate_name,
                safe_gate_name + "        continue-on-error: ${{ true }}\n",
                2,
            ),
            replace_occurrence(
                original,
                "          /usr/bin/python3 -I -B scripts/round6_safe_gate_contract.py --root .\n",
                "          python3 -B scripts/round6_safe_gate_contract.py --root .\n",
                1,
            ),
            replace_occurrence(
                original,
                "          /usr/bin/python3 -I -B scripts/round6_safe_gate_contract.py --root .\n",
                "          python3 -B scripts/round6_safe_gate_contract.py --root .\n",
                2,
            ),
            replace_occurrence(
                original,
                "          /usr/bin/python3 -I -B scripts/round6_safe_gate_contract_test.py\n",
                "          python3 -B scripts/round6_safe_gate_contract_test.py\n",
                1,
            ),
            replace_occurrence(
                original,
                "          /usr/bin/python3 -I -B scripts/round6_safe_gate_contract_test.py\n",
                "          python3 -B scripts/round6_safe_gate_contract_test.py\n",
                2,
            ),
            replace_occurrence(
                original,
                "          /usr/bin/python3 -I -B - <<'PY'\n",
                "          /usr/bin/python3 -I -B -c 'import yaml' <<'PY'\n",
                1,
            ),
            replace_occurrence(
                original,
                "          /usr/bin/python3 -I -B - <<'PY'\n",
                "          /usr/bin/python3 -I -B -c 'import yaml' <<'PY'\n",
                2,
            ),
            original.replace(
                "        shell: bash\n",
                "        shell: sh\n",
                1,
            ),
            original.replace(
                "        shell: bash\n",
                "        shell: sh\n",
                2,
            ).replace("        shell: sh\n", "        shell: bash\n", 1),
            original.replace(
                "/usr/lib/python3/dist-packages/yaml/__init__.py",
                "/tmp/yaml/__init__.py",
                1,
            ),
            replace_occurrence(
                original,
                "/usr/lib/python3/dist-packages/yaml/__init__.py",
                "/tmp/yaml/__init__.py",
                2,
            ),
            original.replace(
                "    if: ${{ needs.admission.outputs.publication_permitted == 'true' }}",
                "    if: ${{ needs.admission.outputs.already_public != 'true' && inputs.publish_rc_release }}",
                1,
            ),
            original.replace(
                "  publication_blocked:\n"
                "    needs:\n"
                "      - admission\n"
                "      - build\n"
                "    if: ${{ needs.admission.outputs.publication_permitted == 'true' }}\n",
                "  publication_blocked:\n"
                "    needs:\n"
                "      - admission\n"
                "      - build\n"
                "    if: ${{ true }}\n",
                1,
            ),
            original.replace(
                "  verify_published:\n"
                "    needs: admission\n"
                "    # Existing Releases are rejected by admission. This legacy read-only\n"
                "    # verifier remains unreachable until an independent-audit gate replaces it.\n"
                "    if: ${{ needs.admission.outputs.publication_permitted == 'true' }}\n",
                "  verify_published:\n"
                "    needs: admission\n"
                "    # Existing Releases are rejected by admission. This legacy read-only\n"
                "    # verifier remains unreachable until an independent-audit gate replaces it.\n"
                "    if: ${{ true }}\n",
                1,
            ),
            original.replace(
                "            printf 'publication_permitted=false\\n'\n",
                "            printf 'publication_permitted=true\\n'\n",
                1,
            ),
            original.replace(
                "      attestations: write\n      contents: read\n      id-token: write",
                "      attestations: write\n      contents: write\n      id-token: write",
                1,
            ),
            original.replace(
                "  publication_blocked:\n",
                "  publication_allowed:\n",
                1,
            ),
            original.replace(
                "No new public Round 9 prerelease can be created by this workflow.",
                "Host evaluation authorizes a public Round 9 prerelease.",
                1,
            ),
            original.replace(
                "            'Required exact-candidate independent-audit evidence is NOT_PROVIDED; the implemented verifier therefore remains fail-closed.' >&2\n"
                "          exit 1\n\n  verify_published:",
                "            'Required exact-candidate independent-audit evidence is NOT_PROVIDED; the implemented verifier therefore remains fail-closed.' >&2\n"
                "          exit 0\n\n  verify_published:",
                1,
            ),
            original.replace(
                "          exit 1\n\n  verify_published:",
                "          gh release create \"$TAG\" dist/*\n"
                "          exit 1\n\n  verify_published:",
                1,
            ),
            original.replace(
                "round9-public-adversarial-report/v13",
                "round9-public-adversarial-report/v12",
                1,
            ),
            original.replace(
                ".round9.corpus.public_adversarial.unmerged_candidate_carriers == 1",
                ".round9.corpus.public_adversarial.unmerged_candidate_carriers >= 1",
                1,
            ),
            original.replace(
                ".round9.corpus.public_adversarial.serialized_route_executions == 120",
                ".round9.corpus.public_adversarial.serialized_route_executions >= 120",
                1,
            ),
            original.replace(
                ".round9.corpus.paired_malicious.recall_basis_points == 10000",
                ".round9.corpus.paired_malicious.recall_basis_points >= 9500",
                1,
            ),
            original.replace(
                "all(.round9.corpus.paired_malicious.per_category[]; .recall_basis_points == 10000)",
                "all(.round9.corpus.paired_malicious.per_category[]; .recall_basis_points >= 9500)",
                1,
            ),
            original.replace(
                'host_ip:"127.0.0.1",host_port:18394,container_port:8317',
                'host_ip:"0.0.0.0",host_port:18394,container_port:8317',
                1,
            ),
            original.replace(
                'round9-external-evaluation/v3',
                'round9-external-evaluation/v1',
                1,
            ),
            original.replace(
                'round9-public-counted-mock/v1',
                'round9-public-counted-mock/v0',
                1,
            ),
            original.replace(
                '.round9.external_evaluation.development_evidence ==',
                '.round9.external_evaluation.development_evidence !=',
                1,
            ),
            original.replace(
                '.round9.counted_mock == .round9.external_evaluation.counted_mock',
                '.round9.counted_mock != .round9.external_evaluation.counted_mock',
                1,
            ),
            original.replace('initial_mode:"audit"', 'initial_mode:"balanced"', 1),
            original.replace(
                'status_required_after_each_phase_transition:true',
                'status_required_after_each_phase_transition:false',
                1,
            ),
            original.replace(
                'round9-external-cpa-runtime-checks/v1',
                'round9-external-cpa-runtime-checks/v0',
                1,
            ),
            original.replace(
                '.round9.counted_mock.not_observed == []',
                '.round9.counted_mock.not_observed != []',
                1,
            ),
            original.replace(
                '.round9.counted_mock.host_results.runtime_checks ==',
                '.round9.counted_mock.host_results.runtime_checks !=',
                1,
            ),
            original.replace(
                'actions/artifacts/${phase1_artifact_id}/zip',
                'actions/artifacts/${HOST_ARTIFACT_ID}/zip',
                1,
            ),
            original.replace(
                'GOTOOLCHAIN: go1.26.4',
                'GOTOOLCHAIN: auto',
                1,
            ),
            original.replace(
                'GOFLAGS: -mod=readonly',
                'GOFLAGS: -mod=mod',
                1,
            ),
            original.replace(
                'build-metadata.json checksums.txt \\',
                'build-metadata.json unexpected.json \\',
                1,
            ),
            original.replace(
                'if len(infos) != 17 or set(names) != expected or len(names) != len(set(names)):',
                'if len(infos) != 18 or set(names) != expected or len(names) != len(set(names)):',
                1,
            ),
            original.replace(
                "          python3 -B scripts/round9_independent_audit_contract_test.py\n",
                "          true\n",
                1,
            ),
            original.replace(
                "          AUDIT_PUBLIC_KEY_BASE64: ${{ vars.ROUND9_INDEPENDENT_AUDITOR_PUBLIC_KEY_BASE64 }}\n",
                "          AUDIT_PUBLIC_KEY_BASE64: ${{ vars.ROUND9_EVALUATOR_PUBLIC_KEY_BASE64 }}\n",
                1,
            ),
            original.replace(
                "          GH_TOKEN: ${{ secrets.ROUND9_INDEPENDENT_AUDIT_REMOTE_VERIFY_TOKEN }}\n",
                "          GH_TOKEN: ${{ github.token }}\n",
                1,
            ),
            original.replace(
                '          if [[ "$missing" == true ]]; then\n',
                "          if true; then\n",
                1,
            ),
            original.replace(
                "            python3 -B scripts/round9_independent_audit_contract.py verify-remote \\\n",
                "            echo PASS \\\n",
                1,
            ),
            original.replace(
                '              --ledger-ruleset-id "$AUDIT_LEDGER_RULESET_ID" \\\n',
                "",
                1,
            ),
            original.replace(
                '            gh attestation verify "$audit_root/$name" --repo "$AUDIT_REPOSITORY" \\\n',
                "            true \\\n",
                1,
            ),
            original.replace(
                '              "round9-independent-audit-ledger-proof.json",\n',
                '              "host-only-pass.json",\n',
                1,
            ),
            original.replace(
                '              --source-digest "$AUDIT_WORKFLOW_SHA" >/dev/null\n',
                "              true\n",
                1,
            ),
            original.replace(CPA_CURRENT_VERSION, CPA_ROUND8_VERSION, 1),
            original.replace(CPA_CURRENT_COMMIT, CPA_ROUND8_COMMIT, 1),
        )
        for mutation in mutations:
            self.assertNotEqual(mutation, original)
            reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
            with mock.patch(
                "round6_safe_gate_contract.ROUND9_RC_WORKFLOW_SHA256",
                reviewed_hash,
            ):
                with self.assertRaises(ContractError):
                    validate_round9_rc_workflow(mutation, path)

    def test_round9_external_host_boundary_mutations_fail_closed_after_hash_review(self):
        root = Path(__file__).resolve().parent.parent
        path = root / ".github/workflows/round9-host-validation.yml"
        original = path.read_text(encoding="utf-8")
        mutations = (
            original.replace(
                "      candidate_identity:\n",
                "      candidate_so_sha256:\n",
                1,
            ),
            original.replace(
                "sudo -n -- /usr/local/libexec/cag-round9-eval-broker evaluate",
                "python3 scripts/candidate-evaluator.py",
                1,
            ),
            original.replace(
                '--candidate-identity "$CANDIDATE_IDENTITY"',
                '--so-sha256 "$CANDIDATE_IDENTITY"',
                1,
            ),
            original.replace(
                '[[ "$DISPATCH_REF" == "refs/tags/$TAG" ]]',
                '[[ "$DISPATCH_REF" == refs/tags/* ]]',
                1,
            ),
            original.replace(
                '[[ "$DISPATCH_SHA" == "$COMMIT" ]]',
                '[[ -n "$DISPATCH_SHA" ]]',
                1,
            ),
            original.replace(
                '[[ "$WORKFLOW_REF" == "${REPOSITORY}/.github/workflows/round9-host-validation.yml@refs/tags/$TAG" ]]',
                '[[ "$WORKFLOW_REF" == *round9-host-validation.yml* ]]',
                1,
            ),
            original.replace(
                '[[ "$WORKFLOW_SHA" == "$COMMIT" ]]',
                '[[ -n "$WORKFLOW_SHA" ]]',
                1,
            ),
            original.replace(
                '--dispatch-ref "$DISPATCH_REF"',
                '--dispatch-ref "refs/tags/$TAG"',
                1,
            ),
            original.replace(
                '--dispatch-sha "$DISPATCH_SHA"',
                '--dispatch-sha "$COMMIT"',
                1,
            ),
            original.replace(
                '--workflow-ref "$WORKFLOW_REF"',
                '--workflow-ref "${REPOSITORY}/.github/workflows/round9-host-validation.yml@refs/tags/$TAG"',
                1,
            ),
            original.replace(
                '--workflow-sha "$WORKFLOW_SHA"',
                '--workflow-sha "$COMMIT"',
                1,
            ),
            original.replace(
                "            /var/lib/cag-round9-eval-broker/public/",
                "            ./candidate-output/",
                1,
            ),
        )
        for mutation in mutations:
            self.assertNotEqual(mutation, original)
            reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
            with mock.patch(
                "round6_safe_gate_contract.ROUND9_HOST_WORKFLOW_SHA256",
                reviewed_hash,
            ):
                with self.assertRaises(ContractError):
                    validate_round9_host_workflow(mutation, path)

    def test_round9_rc_script_fixed_port_and_host_guide_fail_closed_after_hash_review(self):
        root = Path(__file__).resolve().parent.parent
        source = root / "scripts/round6-rc-artifacts.sh"
        original = source.read_text(encoding="utf-8")
        mutations = (
            original.replace(
                'host_ip: "127.0.0.1", host_port: 18394, container_port: 8317',
                'host_ip: "127.0.0.1", host_port: 0, container_port: 8317',
                1,
            ),
            original.replace("      docs/ROUND9_HOST_RUNNER.md\n", "", 1),
            original.replace("Public adversarial v13", "Public adversarial v12", 1),
            original.replace('initial_mode: "audit"', 'initial_mode: "balanced"', 1),
            original.replace(
                "round9-external-cpa-runtime-checks/v1",
                "round9-external-cpa-runtime-checks/v0",
                1,
            ),
            original.replace(
                ".payload.counted_mock.not_observed == []",
                ".payload.counted_mock.not_observed != []",
                1,
            ),
            original.replace(
                ".payload.metrics.runtime_checks ==",
                ".payload.metrics.runtime_checks !=",
                1,
            ),
        )
        names = (
            "release-common.sh",
            "round6-rc-artifacts.sh",
        ) + FORMAL_OPERATION_SCRIPTS + tuple(EXTERNAL_ATTESTATION_SCRIPT_SHA256)
        for mutation in mutations:
            self.assertNotEqual(mutation, original)
            with self.subTest(mutation=hashlib.sha256(mutation.encode("utf-8")).hexdigest()):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                fixture = Path(temporary.name)
                (fixture / "scripts").mkdir()
                for name in names:
                    text = (root / "scripts" / name).read_text(encoding="utf-8")
                    if name == "round6-rc-artifacts.sh":
                        text = mutation
                    (fixture / "scripts" / name).write_text(text, encoding="utf-8")
                reviewed_hash = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.RC_RELEASE_SCRIPT_SHA256",
                    reviewed_hash,
                ):
                    with self.assertRaises(ContractError):
                        validate_release_mode_contracts(fixture)

    def test_rc_artifact_cpa_gate_key_is_derived_from_the_reviewed_lane(self):
        source = (
            Path(__file__).resolve().parent.parent
            / "scripts/round6-rc-artifacts.sh"
        )
        original = source.read_text(encoding="utf-8")
        validate_rc_reproducible_release_asset_contract(original, source)
        mutations = (
            original.replace(
                'cpa_gate_key="rc_gate.cpa_${cpa_version}_primary_source_compatibility=PASS"',
                f'cpa_gate_key="rc_gate.cpa_{CPA_CURRENT_VERSION}_primary_source_compatibility=PASS"',
                1,
            ),
            original.replace(
                '"$cpa_gate_key" \\\n',
                f"'rc_gate.cpa_{CPA_CURRENT_VERSION}_primary_source_compatibility=PASS' \\\n",
                1,
            ),
            original.replace(
                f"    cpa_version='{CPA_ROUND8_VERSION}'\n",
                f"    cpa_version='{CPA_CURRENT_VERSION}'\n",
                1,
            ),
            original.replace(
                f"    cpa_commit='{CPA_ROUND8_COMMIT}'\n",
                f"    cpa_commit='{CPA_CURRENT_COMMIT}'\n",
                1,
            ),
            original.replace(
                f"    cpa_version='{CPA_CURRENT_VERSION}'\n",
                f"    cpa_version='{CPA_ROUND8_VERSION}'\n",
                1,
            ),
            original.replace(
                f"    cpa_commit='{CPA_CURRENT_COMMIT}'\n",
                f"    cpa_commit='{CPA_ROUND8_COMMIT}'\n",
                1,
            ),
        )
        for mutation in mutations:
            self.assertNotEqual(mutation, original)
            with self.assertRaisesRegex(
                ContractError,
                "lane identities|lane-specific CPA gate key|derive the CPA gate key|canonical test summary",
            ):
                validate_rc_reproducible_release_asset_contract(mutation, source)

    def test_round8_host_workflow_security_mutations_fail_closed(self):
        workflow_path = (
            Path(__file__).resolve().parent.parent
            / ".github/workflows/round8-host-validation.yml"
        )
        original = workflow_path.read_text(encoding="utf-8")
        mutations = (
            original.replace(
                "    environment:\n      name: round8-host-validation\n", "", 1
            ),
            original.replace("      - self-hosted\n", "      - ubuntu-24.04\n", 1),
            original.replace(
                "      challenge:\n",
                "      host_evidence_base64:\n"
                "        description: Untrusted raw evidence\n"
                "        required: true\n"
                "        type: string\n"
                "      challenge:\n",
                1,
            ),
            original.replace(
                '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release-rc.yml"',
                '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/untrusted.yml"',
                1,
            ),
            original.replace('--source-ref "refs/tags/$TAG"', '--source-ref "refs/heads/main"', 1),
            original.replace('--source-digest "$EXPECTED_COMMIT"', '--source-digest "$EXPECTED_TREE"', 1),
            original.replace('--daemon-id "$DAEMON_ID"', '--daemon-id untrusted', 1),
            original.replace('--challenge "$HOST_CHALLENGE"', '--challenge 0000', 1),
            original.replace(
                '.execution.sandbox.locality_challenge == "PASS"',
                '.execution.sandbox.locality_challenge == "SKIPPED"',
                1,
            ),
            original.replace(
                "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373",
                "actions/attest-build-provenance@" + "0" * 40,
                1,
            ),
            original.replace(
                "permissions:\n",
                "env:\n  UNREVIEWED_ROOT_ENV: true\n\npermissions:\n",
                1,
            ),
            original.replace(CPA_ROUND8_VERSION, CPA_CURRENT_VERSION, 1),
            original.replace(CPA_ROUND8_COMMIT, CPA_CURRENT_COMMIT, 1),
            original.replace(
                "    runs-on:\n",
                "    container: unreviewed.example/host:latest\n    runs-on:\n",
                1,
            ),
            original.replace(
                "          DAEMON_ID: ${{ vars.ROUND8_DAEMON_ID }}\n",
                "          DAEMON_ID: ${{ inputs.expected_tree }}\n",
                1,
            ),
            original.replace(
                "          persist-credentials: false\n",
                "          persist-credentials: true\n",
                1,
            ),
            original.replace(
                "          subject-path: |\n"
                "            ${{ runner.temp }}/round8-host-output/round8-host-evidence.json\n"
                "            ${{ runner.temp }}/round8-host-output/round8-host-evidence.json.sha256\n",
                "          subject-path: |\n"
                "            ${{ runner.temp }}/round8-host-output/unreviewed.json\n"
                "            ${{ runner.temp }}/round8-host-output/unreviewed.json.sha256\n",
                1,
            ),
            original.replace(
                "          path: |\n"
                "            ${{ runner.temp }}/round8-host-output/round8-host-evidence.json\n"
                "            ${{ runner.temp }}/round8-host-output/round8-host-evidence.json.sha256\n",
                "          path: |\n"
                "            ${{ runner.temp }}/round8-host-output/unreviewed.json\n"
                "            ${{ runner.temp }}/round8-host-output/unreviewed.json.sha256\n",
                1,
            ),
            original.replace(
                "            ' \"$output/round8-host-evidence.json\" >/dev/null\n",
                "            ' \"$output/round8-host-evidence.json\" >/dev/null || true\n",
                1,
            ),
            original.replace(
                "                (.size_in_bytes | type == \"number\" and . > 0 and . <= 268435456)\n",
                "                (.size_in_bytes | type == \"number\" and . > 0)\n",
                1,
            ),
            original.replace(
                "    needs: base-image-supply-chain\n",
                "    needs: unreviewed-base-images\n",
                1,
            ),
            original.replace(
                "sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b",
                "sha256:" + "0" * 64,
                1,
            ),
            original.replace(
                '          docker pull --quiet --platform linux/amd64 "$GO_CANONICAL" >/dev/null\n',
                '          docker pull golang:1.26-bookworm >/dev/null\n',
                1,
            ),
            original.replace(
                "          BASE_ARTIFACT_DIGEST: ${{ needs.base-image-supply-chain.outputs.artifact-digest }}\n",
                "          BASE_ARTIFACT_DIGEST: sha256:" + "0" * 64 + "\n",
                1,
            ),
            original.replace(
                '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/round8-host-validation.yml"',
                '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/untrusted-base.yml"',
                1,
            ),
        )
        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(mutated, original)
                with self.assertRaises(ContractError):
                    validate_round8_host_workflow(mutated, workflow_path)

    def test_active_rc_protected_host_admission_mutations_fail_closed(self):
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        original = workflow_path.read_text(encoding="utf-8")
        mutations = (
            original.replace(
                "    environment:\n      name: round8-rc-publication\n", "", 1
            ),
            original.replace(
                '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/round8-host-validation.yml"',
                '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/untrusted.yml"',
                1,
            ),
            original.replace('--source-ref "refs/tags/$TAG"', '--source-ref "refs/heads/main"', 1),
            original.replace('--source-digest "$EXPECTED_COMMIT"', '--source-digest "$EXPECTED_TREE"', 1),
            original.replace(
                '.execution.challenge == $challenge',
                '.execution.challenge != $challenge',
                1,
            ),
            original.replace(
                '.execution.workflow.run_id == $run_id',
                '.execution.workflow.run_id > 0',
                1,
            ),
            original.replace(
                '.id == $artifact_id and .digest == $digest and .expired == false and',
                '.id == $artifact_id and .expired == false and',
                1,
            ),
        )
        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(mutated, original)
                reviewed_hash = hashlib.sha256(mutated.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.ACTIVE_RC_WORKFLOW_SHA256", reviewed_hash
                ):
                    with self.assertRaises(ContractError):
                        validate_rc_release_workflow(mutated, workflow_path)

    def test_active_rc_host_artifact_zip_mutations_fail_closed_after_hash_review(self):
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        original = workflow_path.read_text(encoding="utf-8")
        mutations = (
            original.replace(
                "            --argjson max_size 1048576 '\n",
                "            --argjson max_size 1073741824 '\n",
                1,
            ),
            original.replace(
                "          host_archive_max_bytes=1048576\n",
                "          host_archive_max_bytes=1073741824\n",
                1,
            ),
            original.replace(
                '          [[ "$downloaded_archive_size" == "$host_archive_size" ]]\n',
                "          true\n",
                1,
            ),
            original.replace("          MAX_ENTRIES = 2\n", "          MAX_ENTRIES = 200\n", 1),
            original.replace(
                "          MAX_ENTRY_EXPANDED_BYTES = 16384\n",
                "          MAX_ENTRY_EXPANDED_BYTES = 1073741824\n",
                1,
            ),
            original.replace(
                "          MAX_TOTAL_EXPANDED_BYTES = 24576\n",
                "          MAX_TOTAL_EXPANDED_BYTES = 1073741824\n",
                1,
            ),
            original.replace(
                "              if len(names) != len(set(names)):\n",
                "              if False:\n",
                1,
            ),
            original.replace(
                "              if len(entries) != MAX_ENTRIES or set(names) != EXPECTED_NAMES:\n",
                "              if len(entries) != MAX_ENTRIES:\n",
                1,
            ),
            original.replace(
                '                      or ".." in path.parts\n',
                "",
                1,
            ),
            original.replace(
                "                      or entry.is_dir()\n",
                "",
                1,
            ),
            original.replace(
                "                  if stat.S_ISLNK(mode):\n",
                "                  if False:\n",
                1,
            ),
            original.replace(
                '                  with host_zip.open(entry, "r") as source, target.open("xb") as output:\n',
                '                  with host_zip.open(entry, "r") as source, target.open("wb") as output:\n',
                1,
            ),
            original.replace(
                '          evidence="$host_dir/round8-host-evidence.json"\n',
                '          unzip -q "$archive" -d "$host_dir"\n'
                '          evidence="$host_dir/round8-host-evidence.json"\n',
                1,
            ),
        )
        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(mutated, original)
                reviewed_hash = hashlib.sha256(mutated.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.ACTIVE_RC_WORKFLOW_SHA256", reviewed_hash
                ):
                    with self.assertRaisesRegex(ContractError, "Host artifact"):
                        validate_rc_release_workflow(mutated, workflow_path)

    def test_active_rc_ordinary_asset_attestation_mutations_fail_closed_after_hash_review(self):
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        original = workflow_path.read_text(encoding="utf-8")
        exact_block = (
            '                --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release-rc.yml" \\\n'
            '                --signer-digest "$EXPECTED_COMMIT" \\\n'
            '                --source-ref "refs/tags/$TAG" \\\n'
            '                --source-digest "$EXPECTED_COMMIT" >/dev/null; then\n'
        )

        def replace_last(text: str, old: str, new: str) -> str:
            prefix, separator, suffix = text.rpartition(old)
            self.assertEqual(separator, old)
            return prefix + new + suffix

        mutations = (
            original.replace(
                '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release-rc.yml"',
                '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/untrusted.yml"',
                1,
            ),
            original.replace(
                exact_block,
                exact_block.replace(
                    '--signer-digest "$EXPECTED_COMMIT"',
                    '--signer-digest "$EXPECTED_TREE"',
                    1,
                ),
                1,
            ),
            original.replace(
                exact_block,
                exact_block.replace(
                    '--source-ref "refs/tags/$TAG"',
                    '--source-ref "refs/heads/main"',
                    1,
                ),
                1,
            ),
            original.replace(
                exact_block,
                exact_block.replace(
                    '--source-digest "$EXPECTED_COMMIT"',
                    '--source-digest "$EXPECTED_TREE"',
                    1,
                ),
                1,
            ),
            replace_last(
                original,
                '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release-rc.yml"',
                '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/untrusted.yml"',
            ),
            original.replace(
                '          [[ "$(grep -c . <<<"$ordinary_assets")" == 17 ]]\n',
                '          [[ "$(grep -c . <<<"$ordinary_assets")" == 19 ]]\n',
                1,
            ),
            original.replace(
                '          done <<<"$ordinary_assets"\n',
                '          done <<<"$expected"\n',
                1,
            ),
            original.replace(
                exact_block,
                '                --repo "$GITHUB_REPOSITORY" >/dev/null; then\n',
                1,
            ),
        )
        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(mutated, original)
                reviewed_hash = hashlib.sha256(mutated.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.ACTIVE_RC_WORKFLOW_SHA256", reviewed_hash
                ):
                    with self.assertRaises(ContractError):
                        validate_rc_release_workflow(mutated, workflow_path)

    def test_active_rc_workflow_security_mutations_fail_closed(self):
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        original = workflow_path.read_text(encoding="utf-8")
        mutations = (
            original.replace("[[ \"$TAG\" == v0.16-rc.2 ]]", "[[ \"$TAG\" == v0.16-rc.* ]]", 1),
            original.replace("--latest=false", "--latest", 1),
            original.replace("--prerelease", "--latest", 1),
            original.replace('[[ "$latest_tag" == v0.15 ]]', '[[ "$latest_tag" != "$TAG" ]]', 1),
            original.replace("ubuntu-24.04", "windows-2025", 1),
            original.replace(CPA_ROUND8_VERSION, "v7.2.92", 1),
            original.replace(".assets | length == 19", ".assets | length >= 1", 1),
            original.replace(
                "rc-release-manifest.json.sha256",
                "formal-release-attestation.json",
                1,
            ),
            original.replace(
                '[[ "$tag_object_sha" == "$EXPECTED_TAG_OBJECT" ]]',
                "true",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "exact reviewed contract"):
                validate_rc_release_workflow(workflow, workflow_path)

    def test_active_rc_two_stage_semantic_mutations_fail_closed_after_hash_review(self):
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        original = workflow_path.read_text(encoding="utf-8")
        mutations = (
            original.replace(
                "  publish:\n"
                "    needs:\n"
                "      - admission\n"
                "      - build\n"
                "    if: ${{ needs.admission.outputs.already_public != 'true' && inputs.publish_rc_release }}\n",
                "  publish:\n"
                "    needs:\n"
                "      - admission\n"
                "      - build\n"
                "    if: ${{ needs.admission.outputs.already_public == 'true' && inputs.publish_rc_release }}\n",
                1,
            ),
            original.replace(
                "permissions:\n  actions: read\n  contents: read\n",
                "permissions:\n  actions: read\n  contents: write\n",
                1,
            ),
            original.replace(
                "      host_run:\n"
                "        description: Protected Round 8 Host validation run and attempt as RUN_ID:RUN_ATTEMPT; required only when publishing\n"
                "        required: false\n",
                "      host_run:\n"
                "        description: Protected Round 8 Host validation run and attempt as RUN_ID:RUN_ATTEMPT; required only when publishing\n"
                "        required: true\n",
                1,
            ),
            original.replace(
                '          [[ "$CI_RUN" =~ ^([1-9][0-9]*):([1-9][0-9]*)$ ]]\n',
                '          [[ -n "$CI_RUN" ]]\n',
                1,
            ),
            original.replace(
                '            [[ "$HOST_RUN" =~ ^([1-9][0-9]*):([1-9][0-9]*)$ ]]\n',
                '            [[ -n "$HOST_RUN" ]]\n',
                1,
            ),
            original.replace(
                '          CI_RUN_ID="${BASH_REMATCH[1]}"\n'
                '          CI_RUN_ATTEMPT="${BASH_REMATCH[2]}"\n',
                '          CI_RUN_ID="${BASH_REMATCH[2]}"\n'
                '          CI_RUN_ATTEMPT="${BASH_REMATCH[1]}"\n',
                1,
            ),
            original.replace(
                "      host_challenge:\n"
                "        description: Fresh lowercase 64-hex challenge bound into the Host workflow evidence\n"
                "        required: false\n"
                "        type: string\n\npermissions:",
                "      host_challenge:\n"
                "        description: Fresh lowercase 64-hex challenge bound into the Host workflow evidence\n"
                "        required: false\n"
                "        type: string\n"
                "      unreviewed_eleventh_input:\n"
                "        description: Unreviewed input\n"
                "        required: false\n"
                "        type: string\n\npermissions:",
                1,
            ),
            original.replace(
                "      - name: Upload exact verified private Host-test candidate\n"
                "        if: ${{ !inputs.publish_rc_release }}\n",
                "      - name: Upload exact verified private Host-test candidate\n"
                "        if: ${{ inputs.publish_rc_release }}\n",
                1,
            ),
            original.replace(
                "            dist/rc-release-manifest.json.sha256\n"
                "          if-no-files-found: error\n"
                "          retention-days: 30\n\n"
                "      - name: Upload exact verified publication-stage RC assets",
                "            dist/rc-release-manifest.json.sha256\n"
                "            dist/round8-host-evidence.json\n"
                "          if-no-files-found: error\n"
                "          retention-days: 30\n\n"
                "      - name: Upload exact verified publication-stage RC assets",
                1,
            ),
            original.replace(
                "            dist/round8-host-evidence.json\n"
                "            dist/round8-host-evidence.json.sha256\n"
                "          if-no-files-found: error\n"
                "          retention-days: 30\n\n"
                "  publish:",
                "            dist/round8-host-evidence.json\n"
                "          if-no-files-found: error\n"
                "          retention-days: 30\n\n"
                "  publish:",
                1,
            ),
            original.replace(
                '            [[ "$HOST_RUN_ID" =~ ^[1-9][0-9]*$ ]]\n',
                "            true\n",
                1,
            ),
            original.replace(
                "                .immutable == true and .prerelease == true and\n",
                "                .prerelease == true and\n",
                1,
            ),
            original.replace(
                '                  "chat_benign_upstream": 1,\n',
                '                  "chat_benign_upstream": 2,\n',
                1,
            ),
            original.replace(
                '                  "usage_queue_allow_delta": 1,\n',
                '                  "usage_queue_allow_delta": 0,\n',
                1,
            ),
            original.replace(
                "if type(actual) is not type(expected):",
                "if actual is not expected:",
                1,
            ),
            original.replace(
                "Host evidence JSON must be canonical UTF-8 without trailing bytes",
                "Host evidence JSON formatting is advisory",
                1,
            ),
            original.replace(
                '                  "unexpected_restart_count": 0,\n',
                '                  "restart_count": 0,\n',
                1,
            ),
            original.replace(
                '              or mock.get("revision") != expected_commit\n',
                '              or mock.get("revision") == expected_commit\n',
                1,
            ),
            original.replace(
                '                      "build_date": cpa_identities["primary"]["build_date"],\n',
                "",
                1,
            ),
            original.replace(
                ".artifact_count == $artifact_count",
                ".artifact_count >= 0",
                1,
            ),
            original.replace(
                "                    paired_malicious_blocked: 42\n",
                "                    paired_malicious_blocked: 41\n",
                1,
            ),
            original.replace(
                "                    purge_wal_passed: true\n",
                "                    purge_wal_passed: false\n",
                1,
            ),
            original.replace(
                '.assets | length == 19 and all(.state == "uploaded")',
                '.assets | length == 17 and all(.state == "uploaded")',
                1,
            ),
            original.replace(
                "      attestations: write\n",
                "      attestations: read\n",
                1,
            ),
            original.replace(
                "      id-token: write\n",
                "      id-token: read\n",
                1,
            ),
            original.replace(
                "      image: docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b\n",
                "      image: docker.io/library/golang:1.26.4-bookworm@sha256:" + "0" * 64 + "\n",
                1,
            ),
            original.replace(
                "  RC_BUILDER_REFERENCE: 'docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b'\n",
                "  RC_BUILDER_REFERENCE: 'docker.io/library/golang:1.26.4-bookworm@sha256:" + "0" * 64 + "'\n",
                1,
            ),
            original.replace(
                "      runner_name: ${{ steps.runner_identity.outputs.runner_name }}\n",
                "",
                1,
            ),
            original.replace(
                "          RC_RUNNER_ENVIRONMENT: ${{ runner.environment }}\n",
                "          RC_RUNNER_ENVIRONMENT: 'github-hosted'\n",
                1,
            ),
            original.replace(
                "          RC_RUNNER_NAME: 'UNRECORDED_EPHEMERAL_GITHUB_HOSTED_RUNNER'\n",
                "          RC_RUNNER_NAME: ${{ runner.name }}\n",
                1,
            ),
            original.replace(
                "          RC_RUNNER_IMAGE_VERSION: 'UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER'\n",
                "          RC_RUNNER_IMAGE_VERSION: 'ubuntu24'\n",
                1,
            ),
            original.replace(
                "          [[ \"$RC_RUNNER_NAME\" == UNRECORDED_EPHEMERAL_GITHUB_HOSTED_RUNNER ]]\n",
                "          true\n",
                1,
            ),
            original.replace(
                "          RC_RUNNER_NAME: ${{ steps.runner_identity.outputs.runner_name }}\n",
                "          RC_RUNNER_NAME: unknown\n",
                1,
            ),
            original.replace(
                "          BUILD_RUNNER_NAME: ${{ needs.build.outputs.runner_name }}\n",
                "          BUILD_RUNNER_NAME: unknown\n",
                1,
            ),
            original.replace(
                r"            name \`${BUILD_RUNNER_NAME}\`",
                r"            name `${BUILD_RUNNER_NAME}`",
                1,
            ),
            original.replace(
                "              .runner_name == $runner_name and\n",
                "",
                1,
            ),
            original.replace(
                "        uses: actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373 # v4.1.1\n",
                "        uses: actions/attest-build-provenance@" + "0" * 40 + " # unreviewed\n",
                1,
            ),
            original.replace(
                "          subject-path: dist/*\n",
                "          subject-path: dist/cyber-abuse-guard-v0.16-rc.2.so\n",
                1,
            ),
            original.replace(
                "      attestations: read\n",
                "      attestations: write\n",
                1,
            ),
            original.replace(
                '              if gh attestation verify "dist/$name" \\\n',
                "          true\n",
                1,
            ),
            original.replace(
                '          [[ "$(jq -r \'.enabled\' <<<"$immutability")" == true ]]\n',
                "          true\n",
                1,
            ),
            original.replace(
                '              [[ "$(jq -r \'.immutable\' <<<"$candidate_final")" == true ]]; then\n',
                '              [[ "$(jq -r \'.draft\' <<<"$candidate_final")" == false ]]; then\n',
                1,
            ),
            original.replace(
                "          publish_request_returned=0\n",
                "          publish_request_returned=1\n",
                1,
            ),
            original.replace(
                '          [[ -n "$final" ]] || {\n',
                "          true || {\n",
                1,
            ),
            original.replace(
                "          trap cleanup_publication_exit EXIT\n",
                "          true\n",
                1,
            ),
            original.replace(
                '            download_and_compare_asset "$name" immutable-final\n',
                "            true\n",
                1,
            ),
            original.replace(
                "            build-metadata.json \\\n"
                "            checksums.txt \\\n"
                "            cyber-abuse-guard-v0.16-rc.2.so \\\n",
                "            build-metadata.json \\\n"
                "            cyber-abuse-guard-v0.16-rc.2.so \\\n",
                1,
            ),
            original.replace(
                "          missing_phase1_assets=()\n",
                "          missing_phase1_assets=(\"${assets[@]}\")\n",
                1,
            ),
            original.replace(
                '            gh release upload "$TAG" "${missing_phase1_assets[@]}" \\\n',
                '            gh release upload "$TAG" "${assets[@]}" --clobber \\\n',
                1,
            ),
            original.replace(
                "          missing_host_assets=()\n",
                "          missing_host_assets=(\"${assets[@]}\")\n",
                1,
            ),
            original.replace(
                '            gh release upload "$TAG" "${missing_host_assets[@]}" \\\n',
                '            gh release upload "$TAG" "${assets[@]}" --clobber \\\n',
                1,
            ),
            original.replace(
                "          Phase 2 Host evidence was generated and signed by the protected Round 8 Host\n",
                "          The Host evidence independently proves production safety and needs no protected runner.\n",
                1,
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(workflow, original)
                reviewed_hash = hashlib.sha256(workflow.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.ACTIVE_RC_WORKFLOW_SHA256",
                    reviewed_hash,
                ):
                    with self.assertRaises(ContractError):
                        validate_rc_release_workflow(workflow, workflow_path)

    def test_active_rc_already_public_recovery_is_read_only_and_byte_exact(self):
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        original = workflow_path.read_text(encoding="utf-8")
        mutations = (
            original.replace(
                '              [[ "$(jq -r \'.immutable\' <<<"$release")" == true ]]\n',
                "              true\n",
                1,
            ),
            original.replace(
                '                download_and_compare_asset "$name" already-public\n',
                "                true\n",
                1,
            ),
            original.replace(
                "              printf '%s\\n' 'already-public immutable RC release verified without mutation'\n"
                "              exit 0\n",
                "              printf '%s\\n' 'already-public immutable RC release verified without mutation'\n"
                "              true\n",
                1,
            ),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            reviewed_hash = hashlib.sha256(workflow.encode("utf-8")).hexdigest()
            with mock.patch(
                "round6_safe_gate_contract.ACTIVE_RC_WORKFLOW_SHA256", reviewed_hash
            ):
                with self.assertRaisesRegex(
                    ContractError,
                    "already-public recovery|19-asset non-latest prerelease|exact reviewed contract",
                ):
                    validate_rc_release_workflow(workflow, workflow_path)

    def test_active_rc_admission_rejects_all_gh_api_write_forms_after_hash_review(self):
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        original = workflow_path.read_text(encoding="utf-8")
        admission_header = "  admission:\n"
        build_header = "  build:\n"
        prefix, remainder = original.split(admission_header, 1)
        admission, suffix = remainder.split(build_header, 1)
        commands = (
            'gh api --method=PATCH "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api -X POST "repos/${GITHUB_REPOSITORY}/releases"',
            'gh api -f draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api -F draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api --field draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api --raw-field draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api --input "$RUNNER_TEMP/request.json" "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api --method "PATCH" "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api "-f" draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            '"/usr/bin/gh" api -F draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'command /usr/bin/gh api --field=draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api --method\\\n=DELETE "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh a\\\npi --input "$RUNNER_TEMP/request.json" "repos/${GITHUB_REPOSITORY}/releases/1"',
            'api_write() { gh api "$@"; }; api_write -f draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertIn("          set -euo pipefail\n", admission)
                indented_command = "".join(
                    f"          {line}\n" for line in command.splitlines()
                )
                mutated_admission = admission.replace(
                    "          set -euo pipefail\n",
                    "          set -euo pipefail\n" + indented_command,
                    1,
                )
                workflow = (
                    prefix
                    + admission_header
                    + mutated_admission
                    + build_header
                    + suffix
                )
                reviewed_hash = hashlib.sha256(workflow.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.ACTIVE_RC_WORKFLOW_SHA256", reviewed_hash
                ):
                    with self.assertRaisesRegex(ContractError, "admission must remain read-only"):
                        validate_rc_release_workflow(workflow, workflow_path)

    def test_active_rc_public_verifier_mutations_fail_closed_after_hash_review(self):
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        original = workflow_path.read_text(encoding="utf-8")
        verifier_header = "  verify_published:\n"
        prefix, verifier = original.split(verifier_header, 1)

        def mutate_verifier(old: str, new: str) -> str:
            self.assertIn(old, verifier)
            return prefix + verifier_header + verifier.replace(old, new, 1)

        mutations = (
            original.replace(
                "    outputs:\n"
                "      already_public: ${{ steps.release_state.outputs.already_public }}\n",
                "",
                1,
            ),
            original.replace(
                "    if: ${{ needs.admission.outputs.already_public != 'true' }}\n",
                "    if: ${{ needs.admission.outputs.already_public == 'true' }}\n",
                1,
            ),
            original.replace(
                "    if: ${{ needs.admission.outputs.already_public != 'true' && inputs.publish_rc_release }}\n",
                "    if: ${{ inputs.publish_rc_release }}\n",
                1,
            ),
            mutate_verifier(
                "    if: ${{ needs.admission.outputs.already_public == 'true' }}\n",
                "    if: ${{ needs.admission.outputs.already_public != 'true' }}\n",
            ),
            mutate_verifier(
                "      contents: read\n",
                "      contents: write\n",
            ),
            mutate_verifier(
                "      image: docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b\n",
                "      image: docker.io/library/golang:1.26.4-bookworm\n",
            ),
            mutate_verifier(
                "          cache: false\n",
                "          cache: true\n",
            ),
            mutate_verifier(
                "            !/docs/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*\n",
                "",
            ),
            mutate_verifier(
                "          make cpa-latest-compat\n",
                "          true\n",
            ),
            mutate_verifier(
                "        run: ./scripts/round6-rc-artifacts.sh\n",
                "        run: 'true'\n",
            ),
            mutate_verifier(
                "          RC_HOST_EVIDENCE_INPUT: ${{ runner.temp }}/round8-host-evidence.json\n",
                "",
            ),
            mutate_verifier(
                '            cmp -s "dist/$name" "$published/$name"\n',
                "            true\n",
            ),
            mutate_verifier(
                '                [[ "sha256:$(sha256sum "$output" | awk \'{print $1}\')" == "$expected_digest" ]]; then\n',
                "                true; then\n",
            ),
            mutate_verifier(
                '              if gh attestation verify "$published/$name" \\\n',
                "              if true; then\n",
            ),
            mutate_verifier(
                '          cmp -s "$RUNNER_TEMP/rc-public-release-fingerprint.json" \\\n'
                '            "$RUNNER_TEMP/rc-public-release-final-fingerprint.json"\n',
                "          true\n",
            ),
            mutate_verifier(
                "          set -euo pipefail\n",
                "          set -euo pipefail\n"
                '          gh release upload "$TAG" dist/*\n',
            ),
            mutate_verifier(
                "          set -euo pipefail\n",
                "          set -euo pipefail\n"
                "          actions/upload-artifact@unreviewed\n",
            ),
            mutate_verifier(
                "          set -euo pipefail\n",
                "          set -euo pipefail\n"
                "          actions/attest-build-provenance@unreviewed\n",
            ),
            mutate_verifier(
                "          set -euo pipefail\n",
                "          set -euo pipefail\n"
                '          gh api --method PATCH "repos/${GITHUB_REPOSITORY}/releases/1"\n',
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(workflow, original)
                reviewed_hash = hashlib.sha256(workflow.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.ACTIVE_RC_WORKFLOW_SHA256",
                    reviewed_hash,
                ):
                    with self.assertRaises(ContractError):
                        validate_rc_release_workflow(workflow, workflow_path)

    def test_active_rc_public_verifier_rejects_all_gh_api_write_forms_after_hash_review(self):
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        original = workflow_path.read_text(encoding="utf-8")
        verifier_header = "  verify_published:\n"
        prefix, verifier = original.split(verifier_header, 1)
        commands = (
            'gh api --method=DELETE "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api -X PUT "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api -f draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api -F draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api --field draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api --raw-field draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api --input "$RUNNER_TEMP/request.json" "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api -X "PUT" "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api "--raw-field" draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'env GH_TOKEN="$GH_TOKEN" /usr/bin/gh api -fdraft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh api --fi\\\neld draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            'gh a\\\npi --method POST "repos/${GITHUB_REPOSITORY}/releases/1"',
            'api_write() { command gh api "$@"; }; api_write --input "$RUNNER_TEMP/request.json" "repos/${GITHUB_REPOSITORY}/releases/1"',
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertIn("          set -euo pipefail\n", verifier)
                indented_command = "".join(
                    f"          {line}\n" for line in command.splitlines()
                )
                mutated_verifier = verifier.replace(
                    "          set -euo pipefail\n",
                    "          set -euo pipefail\n" + indented_command,
                    1,
                )
                workflow = prefix + verifier_header + mutated_verifier
                reviewed_hash = hashlib.sha256(workflow.encode("utf-8")).hexdigest()
                with mock.patch(
                    "round6_safe_gate_contract.ACTIVE_RC_WORKFLOW_SHA256", reviewed_hash
                ):
                    with self.assertRaisesRegex(
                        ContractError, "public verifier must not mutate"
                    ):
                        validate_rc_release_workflow(workflow, workflow_path)

    def test_active_rc_read_only_gh_api_allows_structurally_safe_forms_after_hash_review(self):
        workflow_path = Path(__file__).resolve().parent.parent / ACTIVE_RC_WORKFLOW_PATH
        original = workflow_path.read_text(encoding="utf-8")
        commands = (
            'gh api "repos/${GITHUB_REPOSITORY}/releases" | jq -f filter.jq',
            '# gh api -f draft=false "repos/${GITHUB_REPOSITORY}/releases/1"',
            "printf '%s\\n' 'gh api --input request.json'",
            'command "/usr/bin/gh" api --method "GET" --field page=2 '
            '"repos/${GITHUB_REPOSITORY}/releases"',
            'gh api -F page=2 --method=GET "repos/${GITHUB_REPOSITORY}/releases"',
        )
        job_boundaries = (
            ("  admission:\n", "  build:\n"),
            ("  verify_published:\n", None),
        )
        for job_header, next_header in job_boundaries:
            prefix, remainder = original.split(job_header, 1)
            if next_header is None:
                job_text, suffix = remainder, ""
            else:
                job_text, trailing = remainder.split(next_header, 1)
                suffix = next_header + trailing
            for command in commands:
                with self.subTest(job=job_header.strip(), command=command):
                    indented_command = "".join(
                        f"          {line}\n" for line in command.splitlines()
                    )
                    mutated_job = job_text.replace(
                        "          set -euo pipefail\n",
                        "          set -euo pipefail\n" + indented_command,
                        1,
                    )
                    workflow = prefix + job_header + mutated_job + suffix
                    reviewed_hash = hashlib.sha256(workflow.encode("utf-8")).hexdigest()
                    with mock.patch(
                        "round6_safe_gate_contract.ACTIVE_RC_WORKFLOW_SHA256",
                        reviewed_hash,
                    ):
                        validate_rc_release_workflow(workflow, workflow_path)

    def test_archived_rc_workflow_mutation_fails_closed(self):
        workflow_path = Path(__file__).resolve().parent.parent / ARCHIVED_RC_WORKFLOW_PATH
        original = workflow_path.read_text(encoding="utf-8")
        mutations = (
            original.replace("[[ \"$TAG\" == v0.15-rc.2 ]]", "[[ \"$TAG\" == v0.15-rc.* ]]", 1),
            original.replace("--latest=false", "--latest", 1),
            original.replace("contents: write", "contents: read", 1),
            original.replace("make cpa-host-fixture-contract cpa-latest-compat", "true", 1),
        )
        for workflow in mutations:
            self.assertNotEqual(workflow, original)
            with self.assertRaisesRegex(ContractError, "exact reviewed contract"):
                validate_archived_rc_workflow(workflow, workflow_path)


if __name__ == "__main__":
    unittest.main()
