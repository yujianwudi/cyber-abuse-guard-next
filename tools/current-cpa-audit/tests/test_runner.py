from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))
sys.path.insert(0, str(HERE))

import run
from audit_contract import canonical_bytes, sha256_bytes
from fixtures import manifest


class RunnerPureTests(unittest.TestCase):
    def test_runtime_config_has_only_counted_mock(self) -> None:
        raw = run.cpa_yaml("balanced", "client", "management", "upstream").decode("utf-8")
        self.assertIn('base-url: "http://mock:18080/v1"', raw)
        self.assertIn("request-log: false", raw)
        self.assertIn("logging-to-file: false", raw)
        self.assertIn('data_dir": "/cag/audit"', raw)
        for marker in ("api.openai.com", "oauth", "provider.example"):
            self.assertNotIn(marker, raw.lower())
        dockerfile = (TOOL / "Dockerfile.mock").read_text("utf-8")
        self.assertIn(
            'ENTRYPOINT ["python3", "-I", "-S", "-B", '
            '"/opt/cag-audit/counted_mock.py"]',
            dockerfile,
        )

    def test_internal_target_rejects_loopback_and_non_rfc1918(self) -> None:
        self.assertEqual(run.internal_base("172.20.0.2", 8317), "http://172.20.0.2:8317")
        for address in ("127.0.0.1", "192.0.2.1", "not-an-ip"):
            with self.subTest(address=address), self.assertRaises(run.AuditFailure):
                run.internal_base(address, 8317)

    def test_runner_bundle_identity_is_complete(self) -> None:
        identity = run.runner_identities()
        self.assertEqual(
            set(identity),
            {
                "audit_contract_sha256",
                "bundle_sha256",
                "machine_schema_sha256",
                "mock_source_sha256",
                "policy_sha256",
                "run_source_sha256",
            },
        )
        self.assertTrue(all(len(value) == 64 and value.strip("0") for value in identity.values()))

    def test_owned_tree_cleanup_does_not_remove_parent(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            owned = Path(parent) / "runtime"
            (owned / "nested").mkdir(parents=True)
            (owned / "nested" / "state").write_text("first-party", encoding="utf-8")
            self.assertEqual(run.remove_owned_tree(owned), 1)
            self.assertFalse(owned.exists())
            self.assertTrue(Path(parent).exists())

    def test_evidence_directory_binding_rejects_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            evidence = root / "evidence"
            moved = root / "moved"
            binding = run.BoundEvidenceDirectory.create(evidence)
            try:
                evidence.rename(moved)
                evidence.mkdir(mode=0o700)
                with self.assertRaises(run.AuditFailure):
                    binding.verify_path()
                run.write_exclusive(binding.bound_path / "bound-canary", b"bound")
                self.assertTrue((moved / "bound-canary").is_file())
                self.assertFalse((evidence / "bound-canary").exists())
            finally:
                binding.close()

        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            evidence = root / "evidence"
            moved = root / "moved-before-bind"
            original_open = run.os.open

            def replace_before_child_open(
                path: object, flags: int, *args: object, **kwargs: object
            ) -> int:
                if path == "evidence" and kwargs.get("dir_fd") is not None:
                    evidence.rename(moved)
                    evidence.mkdir(mode=0o700)
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(run.os, "open", side_effect=replace_before_child_open):
                with self.assertRaises(run.AuditFailure):
                    run.BoundEvidenceDirectory.create(evidence)

    @unittest.skipUnless(os.name == "posix", "Linux permission contract")
    def test_evidence_directory_binding_rejects_nonprivate_parent(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            evidence = root / "evidence"
            root.chmod(0o770)
            try:
                with self.assertRaisesRegex(
                    run.AuditFailure, "parent must be a private real directory"
                ):
                    run.BoundEvidenceDirectory.create(evidence)
                self.assertFalse(evidence.exists())
            finally:
                root.chmod(0o700)

    @unittest.skipUnless(os.name == "posix", "Linux permission contract")
    def test_evidence_directory_binding_rejects_parent_mode_drift(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            evidence = root / "evidence"
            binding = run.BoundEvidenceDirectory.create(evidence)
            try:
                root.chmod(0o750)
                with self.assertRaisesRegex(
                    run.AuditFailure, "identity changed during the audit"
                ):
                    binding.verify_path()
            finally:
                root.chmod(0o700)
                binding.close()

    @unittest.skipUnless(os.name == "posix", "Linux absolute ancestor contract")
    def test_evidence_directory_binding_rejects_symlink_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            real = root / "real"
            alias = root / "alias"
            private = real / "private"
            private.mkdir(parents=True, mode=0o700)
            private.chmod(0o700)
            alias.symlink_to(real, target_is_directory=True)
            evidence = alias / "private" / "evidence"
            with self.assertRaisesRegex(
                run.AuditFailure, "ancestors must be real directories"
            ):
                run.BoundEvidenceDirectory.create(evidence)
            self.assertFalse((private / "evidence").exists())

    @unittest.skipUnless(os.name == "posix", "Linux absolute ancestor contract")
    def test_evidence_directory_binding_rejects_ancestor_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            evidence = root / "evidence"
            moved = root.parent / f"{root.name}-moved"
            binding = run.BoundEvidenceDirectory.create(evidence)
            try:
                root.rename(moved)
                root.mkdir(mode=0o700)
                with self.assertRaisesRegex(
                    run.AuditFailure, "identity changed during the audit"
                ):
                    binding.verify_path()
            finally:
                binding.close()
                if root.exists():
                    root.rmdir()
                if moved.exists():
                    moved.rename(root)

    @unittest.skipUnless(os.name == "posix", "Linux proc-fd contract")
    def test_evidence_bound_path_is_visible_to_an_independent_process(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            evidence = Path(parent) / "evidence"
            binding = run.BoundEvidenceDirectory.create(evidence)
            try:
                result = run.run_process(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        (
                            "from pathlib import Path; import sys; "
                            "Path(sys.argv[1], 'external-canary').write_text("
                            "'external', encoding='utf-8')"
                        ),
                        str(binding.bound_path),
                    ]
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    (evidence / "external-canary").read_text("utf-8"), "external"
                )
                binding.verify_path()
            finally:
                binding.close()

    @unittest.skipUnless(os.name == "posix", "Linux private environment-file contract")
    def test_ephemeral_mock_environment_is_private_and_removed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            root.chmod(0o700)
            expected = (
                "CAG_MOCK_CONTROL_TOKEN=control-secret\n"
                "CAG_MOCK_UPSTREAM_KEY=upstream-secret\n"
            )
            with run.ephemeral_mock_environment(
                root, "control-secret", "upstream-secret"
            ) as environment_file:
                self.assertEqual(environment_file.name, ".mock-environment")
                self.assertEqual(environment_file.read_text("utf-8"), expected)
                info = environment_file.lstat()
                self.assertEqual(info.st_mode & 0o777, 0o600)
                self.assertEqual(info.st_nlink, 1)
                result = run.run_process(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())",
                        str(environment_file),
                    ]
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected + "\n")
            self.assertFalse((root / ".mock-environment").exists())

            existing = root / ".mock-environment"
            existing.write_text("preserve", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                with run.ephemeral_mock_environment(root, "control", "upstream"):
                    self.fail("pre-existing environment file must not be opened")
            self.assertEqual(existing.read_text("utf-8"), "preserve")

            existing.unlink()
            with self.assertRaisesRegex(run.AuditFailure, "cannot be represented"):
                with run.ephemeral_mock_environment(root, "control\nleak", "upstream"):
                    self.fail("invalid environment value must not be opened")
            self.assertFalse(existing.exists())

    @unittest.skipUnless(os.name == "posix", "Linux private environment-file contract")
    def test_ephemeral_mock_environment_fails_closed_on_identity_mutation(self) -> None:
        def mutate_replace(path: Path, root: Path) -> None:
            path.rename(root / "original-moved")
            path.write_text("replacement", encoding="utf-8")
            path.chmod(0o600)

        def mutate_hardlink(path: Path, root: Path) -> None:
            os.link(path, root / "second-link")

        def mutate_unlink(path: Path, root: Path) -> None:
            del root
            path.unlink()

        def mutate_mode(path: Path, root: Path) -> None:
            del root
            path.chmod(0o640)

        def mutate_content(path: Path, root: Path) -> None:
            del root
            path.write_text("tampered", encoding="utf-8")

        variants = (
            ("replace", mutate_replace, "changed before cleanup"),
            ("hardlink", mutate_hardlink, "changed before cleanup"),
            ("unlink", mutate_unlink, "disappeared before cleanup"),
            ("mode", mutate_mode, "changed before cleanup"),
            ("content", mutate_content, "changed before cleanup"),
        )
        for label, mutation, expected in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                root.chmod(0o700)
                environment_file: Path | None = None
                with self.assertRaisesRegex(run.AuditFailure, expected):
                    with run.ephemeral_mock_environment(
                        root, "control-secret", "upstream-secret"
                    ) as current:
                        environment_file = current
                        mutation(current, root)
                self.assertIsNotNone(environment_file)
                if label == "replace":
                    self.assertEqual(
                        (root / ".mock-environment").read_text("utf-8"),
                        "replacement",
                    )
                    self.assertTrue((root / "original-moved").is_file())
                elif label == "hardlink":
                    self.assertTrue((root / ".mock-environment").is_file())
                    self.assertTrue((root / "second-link").is_file())
                elif label == "unlink":
                    self.assertFalse((root / ".mock-environment").exists())
                else:
                    self.assertTrue((root / ".mock-environment").is_file())

    @unittest.skipUnless(os.name == "posix", "Linux private environment-file contract")
    def test_owned_runtime_cleanup_removes_failed_env_file_and_internal_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            runtime = Path(parent) / "runtime"
            runtime.mkdir(mode=0o700)
            with self.assertRaisesRegex(run.AuditFailure, "changed before cleanup"):
                with run.ephemeral_mock_environment(
                    runtime, "control-secret", "upstream-secret"
                ) as environment_file:
                    os.link(environment_file, runtime / "second-link")
            self.assertEqual(run.remove_owned_tree(runtime), 2)
            self.assertFalse(runtime.exists())

    @unittest.skipUnless(os.name == "posix", "Linux private environment-file contract")
    def test_mock_start_argv_never_contains_credentials_and_env_file_is_removed(self) -> None:
        for docker_fails in (False, True):
            with self.subTest(docker_fails=docker_fails), tempfile.TemporaryDirectory() as parent:
                cold_root = Path(parent)
                cold_root.chmod(0o700)
                harness = object.__new__(run.Harness)
                harness.config = {
                    "identities": {
                        "mock": {"image_ref": "example/mock@sha256:" + "1" * 64}
                    }
                }
                harness.mock_name = "unit-mock"
                harness.network_name = "unit-network"
                harness.control_token = "control-secret"
                harness.upstream_key = "upstream-secret"
                harness.failure_stage = "initialization"
                harness.common_container_args = mock.Mock(return_value=["run", "--detach"])
                harness.docker = mock.Mock()
                captured: dict[str, object] = {}

                def docker_run(arguments: list[str], *, timeout: int = 60) -> object:
                    del timeout
                    captured["arguments"] = list(arguments)
                    index = arguments.index("--env-file")
                    environment_file = Path(arguments[index + 1])
                    captured["path"] = environment_file
                    captured["content"] = environment_file.read_text("utf-8")
                    self.assertEqual(environment_file.lstat().st_mode & 0o777, 0o600)
                    if docker_fails:
                        raise run.AuditFailure("synthetic Docker failure")
                    return object()

                harness.docker.run.side_effect = docker_run

                def after_docker(*args: object, **kwargs: object) -> str:
                    del args, kwargs
                    self.assertFalse(Path(captured["path"]).exists())
                    raise run.AuditFailure("stop after Mock start")

                with mock.patch.object(run, "container_ip", side_effect=after_docker):
                    with self.assertRaises(run.AuditFailure):
                        harness.start_cold(cold_root, "audit")

                arguments = [str(value) for value in captured["arguments"]]
                self.assertIn("--env-file", arguments)
                self.assertNotIn("control-secret", "\n".join(arguments))
                self.assertNotIn("upstream-secret", "\n".join(arguments))
                self.assertEqual(
                    captured["content"],
                    "CAG_MOCK_CONTROL_TOKEN=control-secret\n"
                    "CAG_MOCK_UPSTREAM_KEY=upstream-secret\n",
                )
                self.assertFalse((cold_root / ".mock-environment").exists())

    def test_readiness_requires_a_clean_cag_candidate(self) -> None:
        harness = object.__new__(run.Harness)
        harness.cpa_url = "http://172.20.0.2:8317"
        harness.management_key = "management"
        harness.readiness_state_sha256 = None
        harness.config = {
            "identities": {
                "cag": {"commit": "1" * 40},
                "cpa": {
                    "commit": "a88197f845c979132c8978ea223c6af05cc81536",
                    "tag": "v7.2.116",
                },
            }
        }
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
            "commit": "1" * 40,
            "dirty": False,
            "enabled": True,
            "mode": "audit",
            "enforcement_ready": True,
            "operational_ready": True,
            "audit_degraded": False,
            "persistence_degraded": False,
            "audit": {
                "healthy": True,
                "degraded": False,
                "schema_version": 6,
                "persistence_verified": True,
            },
            "raw_capture": {"enabled": False},
        }
        headers = {
            "x-cpa-version": "v7.2.116",
            "x-cpa-commit": "a88197f845c979132c8978ea223c6af05cc81536",
        }
        with mock.patch.object(
            run,
            "http_json",
            side_effect=[(plugins, headers, 0.1), (status, headers, 0.1)],
        ):
            self.assertEqual(harness.wait_ready("audit"), status)

        dirty_status = dict(status)
        dirty_status["dirty"] = True
        with (
            mock.patch.object(
                run,
                "http_json",
                side_effect=[
                    (plugins, headers, 0.1),
                    (dirty_status, headers, 0.1),
                ],
            ),
            mock.patch.object(run.time, "monotonic", side_effect=[0.0, 0.0, 46.0]),
            mock.patch.object(run.time, "sleep"),
        ):
            with self.assertRaisesRegex(
                run.AuditFailure, "readiness did not converge for audit"
            ):
                harness.wait_ready("audit")
        self.assertRegex(harness.readiness_state_sha256 or "", r"^[0-9a-f]{64}$")

    @unittest.skipUnless(os.name == "posix", "Linux proc-fd and Docker path contract")
    def test_docker_bind_source_uses_verified_normal_path(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            evidence = Path(parent) / "evidence"
            moved = Path(parent) / "moved"
            binding = run.BoundEvidenceDirectory.create(evidence)
            try:
                bound_source = binding.bound_path / ".runtime" / "cold-1" / "auth"
                bound_source.mkdir(parents=True, mode=0o700)
                for directory in (
                    binding.bound_path / ".runtime",
                    binding.bound_path / ".runtime" / "cold-1",
                    bound_source,
                ):
                    directory.chmod(0o700)
                harness = object.__new__(run.Harness)
                harness.evidence_binding = binding
                harness.evidence_dir = binding.bound_path
                harness.host_evidence_dir = evidence
                normal_source, identity = harness.docker_bind_source(bound_source)
                self.assertEqual(
                    normal_source,
                    evidence / ".runtime" / "cold-1" / "auth",
                )
                self.assertNotIn("/proc/", str(normal_source))

                evidence.rename(moved)
                evidence.mkdir(mode=0o700)
                with self.assertRaisesRegex(
                    run.AuditFailure, "identity changed during the audit"
                ):
                    harness.docker_bind_source(
                        bound_source, expected_identity=identity
                    )
            finally:
                binding.close()

    @unittest.skipUnless(os.name == "posix", "Linux Docker bind-mount contract")
    def test_cpa_bind_mounts_use_normal_paths_and_verify_inspect(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            evidence = Path(parent) / "evidence"
            binding = run.BoundEvidenceDirectory.create(evidence)
            try:
                runtime = binding.bound_path / ".runtime"
                cold_root = runtime / "cold-1"
                for relative in (
                    Path("."),
                    Path("plugins"),
                    Path("config"),
                    Path("auth"),
                    Path("audit"),
                    Path("secrets"),
                ):
                    directory = cold_root / relative
                    directory.mkdir(parents=True, mode=0o700)
                    directory.chmod(0o700)
                runtime.chmod(0o700)
                cold_root.chmod(0o700)

                harness = object.__new__(run.Harness)
                harness.evidence_binding = binding
                harness.evidence_dir = binding.bound_path
                harness.host_evidence_dir = evidence
                harness.active_cpa_mounts = {}
                harness.cpa_name = "unit-run-cpa"
                harness.docker = mock.Mock()
                arguments = harness.cpa_bind_mount_args(cold_root)
                mount_values = [
                    arguments[index + 1]
                    for index, value in enumerate(arguments)
                    if value == "--mount"
                ]
                self.assertEqual(len(mount_values), 5)
                self.assertTrue(
                    all(
                        f"src={evidence / '.runtime' / 'cold-1'}" in value
                        for value in mount_values
                    )
                )
                self.assertTrue(all("/proc/" not in value for value in mount_values))

                mounts = []
                for destination, (_, host_source, read_only, _) in (
                    harness.active_cpa_mounts.items()
                ):
                    mounts.append(
                        {
                            "Destination": destination,
                            "Propagation": "rprivate",
                            "RW": not read_only,
                            "Source": str(host_source),
                            "Type": "bind",
                        }
                    )
                tmpfs_mount = {
                    "Destination": "/tmp",
                    "RW": True,
                    "Source": "",
                    "Type": "tmpfs",
                }
                def set_inspect(
                    values: list[dict[str, object]],
                    tmpfs_options: str = "rw,noexec,nosuid,nodev,size=64m",
                ) -> None:
                    harness.docker.inspect.return_value = {
                        "HostConfig": {"Tmpfs": {"/tmp": tmpfs_options}},
                        "Mounts": values,
                    }

                set_inspect(mounts)
                harness.verify_cpa_bind_mounts()
                set_inspect([*mounts, dict(tmpfs_mount)])
                harness.verify_cpa_bind_mounts()

                variants: list[tuple[str, list[dict[str, object]], str]] = []

                wrong_source = [dict(item) for item in mounts]
                wrong_source[0]["Source"] = str(binding.bound_path)
                variants.append(
                    (
                        "wrong source",
                        wrong_source,
                        "source, identity, or access mode drifted",
                    )
                )

                readonly_is_rw = [dict(item) for item in mounts]
                readonly_is_rw[0]["RW"] = True
                variants.append(
                    (
                        "read-only mount is writable",
                        readonly_is_rw,
                        "source, identity, or access mode drifted",
                    )
                )

                writable_is_readonly = [dict(item) for item in mounts]
                writable_is_readonly[2]["RW"] = False
                variants.append(
                    (
                        "writable mount is read-only",
                        writable_is_readonly,
                        "source, identity, or access mode drifted",
                    )
                )

                wrong_propagation = [dict(item) for item in mounts]
                wrong_propagation[0]["Propagation"] = "rshared"
                variants.append(
                    (
                        "bind propagation drift",
                        wrong_propagation,
                        "source, identity, or access mode drifted",
                    )
                )

                variants.append(
                    (
                        "missing bind",
                        [dict(item) for item in mounts[1:]],
                        "destination set is not closed",
                    )
                )

                extra_bind = [dict(item) for item in mounts]
                extra_bind.append(
                    {
                        "Destination": "/unexpected",
                        "Propagation": "rprivate",
                        "RW": False,
                        "Source": str(evidence),
                        "Type": "bind",
                    }
                )
                variants.append(
                    ("extra bind", extra_bind, "destination set is not closed")
                )

                duplicate_bind = [dict(item) for item in mounts]
                duplicate_bind.append(dict(mounts[0]))
                variants.append(
                    (
                        "duplicate bind destination",
                        duplicate_bind,
                        "destinations are not unique",
                    )
                )

                wrong_type = [dict(item) for item in mounts]
                wrong_type[0]["Type"] = "volume"
                variants.append(
                    ("unexpected volume", wrong_type, "unexpected non-bind mount")
                )

                duplicate_tmpfs = [dict(item) for item in mounts]
                duplicate_tmpfs.extend([dict(tmpfs_mount), dict(tmpfs_mount)])
                variants.append(
                    (
                        "duplicate tmpfs",
                        duplicate_tmpfs,
                        "unexpected non-bind mount",
                    )
                )

                for label, observed, message in variants:
                    with self.subTest(label=label):
                        set_inspect(observed)
                        with self.assertRaisesRegex(run.AuditFailure, message):
                            harness.verify_cpa_bind_mounts()

                set_inspect(mounts, "rw,noexec,nosuid,nodev,size=32m")
                with self.assertRaisesRegex(
                    run.AuditFailure, "tmpfs access or size contract drifted"
                ):
                    harness.verify_cpa_bind_mounts()

                invalid_host_configs: list[tuple[str, dict[str, object]]] = [
                    ("missing HostConfig tmpfs", {}),
                    ("non-object HostConfig tmpfs", {"Tmpfs": []}),
                    (
                        "extra HostConfig tmpfs destination",
                        {
                            "Tmpfs": {
                                "/tmp": "rw,noexec,nosuid,nodev,size=64m",
                                "/unexpected": "rw,size=1m",
                            }
                        },
                    ),
                ]
                for label, invalid_host_config in invalid_host_configs:
                    with self.subTest(label=label):
                        harness.docker.inspect.return_value = {
                            "HostConfig": invalid_host_config,
                            "Mounts": mounts,
                        }
                        with self.assertRaisesRegex(
                            run.AuditFailure, "tmpfs destination set is not closed"
                        ):
                            harness.verify_cpa_bind_mounts()

                auth = evidence / ".runtime" / "cold-1" / "auth"
                moved_auth = evidence / ".runtime" / "cold-1" / "moved-auth"
                auth.rename(moved_auth)
                auth.mkdir(mode=0o700)
                set_inspect(mounts)
                with self.assertRaisesRegex(
                    run.AuditFailure, "identity changed after daemon handoff"
                ):
                    harness.verify_cpa_bind_mounts()
            finally:
                binding.close()

    @unittest.skipUnless(os.name == "posix", "Linux private runtime contract")
    def test_prepare_cold_runtime_makes_every_mount_ancestor_private(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            artifact = root / "candidate.so"
            artifact.write_bytes(b"candidate")
            harness = object.__new__(run.Harness)
            harness.runtime_root = root / "runtime"
            harness.runtime_root.mkdir(mode=0o700)
            harness.config = {
                "identities": {"cag": {"so_sha256": sha256_bytes(b"candidate")}},
                "paths": {"cag_so": str(artifact)},
            }
            cold_root, runtime_hash = harness.prepare_cold_runtime(1, "balanced")
            self.assertRegex(runtime_hash, r"^[0-9a-f]{64}$")
            for directory in (
                harness.runtime_root,
                cold_root,
                cold_root / "plugins",
                cold_root / "plugins" / "linux",
                cold_root / "plugins" / "linux" / "amd64",
                cold_root / "config",
                cold_root / "auth",
                cold_root / "audit",
                cold_root / "secrets",
            ):
                self.assertEqual(directory.stat().st_mode & 0o077, 0)

    def test_validated_corpus_cleanup_removes_nerv_text_and_retains_no_body(self) -> None:
        value = manifest()
        canary = b"NERV_COMPLETE_TEXT_CANARY_MUST_NOT_REMAIN"
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            corpus = root / "corpus"
            corpus.mkdir()
            payloads: dict[str, bytes] = {}
            for case in value["semantic_cases"]:
                source = case["source"]
                relative = source["corpus_file"]
                payload = payloads.setdefault(
                    relative, canary + relative.encode("utf-8")
                )
                source["text_bytes"] = len(payload)
                source["text_sha256"] = sha256_bytes(payload)
                if source["archive_member"] is None:
                    source["source_sha256"] = source["text_sha256"]
                (root / relative).write_bytes(payload)
            root_info = root.stat()
            corpus_info = corpus.stat()
            value["filesystem_identity"] = {
                "acquisition_root": {
                    "device": root_info.st_dev,
                    "inode": root_info.st_ino,
                },
                "corpus_directory": {
                    "device": corpus_info.st_dev,
                    "inode": corpus_info.st_ino,
                },
            }
            removed, retained = run.remove_manifest_corpus(value, root)
            self.assertEqual(removed, value["source_count"])
            self.assertFalse(retained)
            self.assertFalse(corpus.exists())
            self.assertTrue(root.exists())
            self.assertNotIn(canary, canonical_bytes(value))


if __name__ == "__main__":
    unittest.main()
