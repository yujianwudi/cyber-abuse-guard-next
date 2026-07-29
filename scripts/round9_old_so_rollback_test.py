#!/usr/bin/env python3
"""Unit tests for the synthetic Round 9 historical-SO rollback helpers."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest

from round9_old_so_rollback import (
    GateError,
    HISTORICAL_REPOSITORY,
    HISTORICAL_SOURCE_CAPSULE,
    HISTORICAL_SOURCE_CAPSULE_SHA256,
    HISTORICAL_SOURCE_DATE_EPOCH,
    HISTORICAL_SOURCE_FILE_COUNT,
    MANIFEST_SCHEMA,
    ROLLBACK_INSTRUCTION,
    SENTINEL_CAPTURE_ID,
    SENTINEL_EVENT_ID,
    SENTINEL_PREVIEW,
    SENTINEL_PREVIEW_SHA256,
    inspect_database,
    restore_backup,
    validate_manifest,
)


class RollbackSourceContractTests(unittest.TestCase):
    def test_historical_source_uses_only_the_reviewed_source_capsule(self) -> None:
        root = Path(__file__).resolve().parent.parent
        script = (root / "scripts" / "round9-old-so-rollback-gate.sh").read_text(
            encoding="utf-8"
        )
        documentation = (root / "docs" / "ROUND9_OLD_SO_ROLLBACK_GATE.md").read_text(
            encoding="utf-8"
        )
        workflow = (root / ".github" / "workflows" / "policy-gate.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            f"historical_repository='{HISTORICAL_REPOSITORY}'", script
        )
        for required in (
            f"historical_source_capsule_relative='{HISTORICAL_SOURCE_CAPSULE}'",
            f"historical_source_capsule_sha256='{HISTORICAL_SOURCE_CAPSULE_SHA256}'",
            f"historical_source_file_count='{HISTORICAL_SOURCE_FILE_COUNT}'",
            f"historical_source_date_epoch='{HISTORICAL_SOURCE_DATE_EPOCH}'",
            'find "$historical_source_capsule" ! -type d ! -type f',
            'find "$historical_source_capsule" -type f -print0',
            'tar -cf - -C "$historical_source_capsule" .',
            "github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.Version",
            '--repository "$historical_repository"',
            '--source-capsule "$historical_source_capsule_relative"',
            '--source-capsule-sha256 "$historical_source_capsule_sha256"',
        ):
            self.assertIn(required, script)

        for forbidden in (
            'git -C "$history_repo"',
            "fetch --no-tags",
            "ls-remote --tags",
            "ROUND9_OLD_SO_VERIFY_REMOTE",
            "github.com/yujianwudi/cyber-abuse-guard-next/internal/buildinfo.Version",
        ):
            self.assertNotIn(forbidden, script)

        capsule = root / HISTORICAL_SOURCE_CAPSULE
        entries = tuple(capsule.rglob("*"))
        self.assertTrue(capsule.is_dir())
        self.assertFalse(any(entry.is_symlink() for entry in entries))
        files = tuple(sorted(entry for entry in entries if entry.is_file()))
        self.assertEqual(len(files), HISTORICAL_SOURCE_FILE_COUNT)
        relative_paths = tuple(path.relative_to(capsule).as_posix() for path in files)
        forbidden_path_tokens = (
            "evaluation",
            "holdout",
            "consumed",
            "private",
            "blind",
            "retired",
            "testdata",
        )
        self.assertFalse(
            any(
                token in component.lower()
                for relative in relative_paths
                for component in Path(relative).parts
                for token in forbidden_path_tokens
            )
        )
        aggregate = "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n"
            for path, relative in zip(files, relative_paths, strict=True)
        )
        self.assertEqual(
            hashlib.sha256(aggregate.encode("utf-8")).hexdigest(),
            HISTORICAL_SOURCE_CAPSULE_SHA256,
        )

        self.assertIn(HISTORICAL_REPOSITORY, documentation)
        self.assertIn(HISTORICAL_SOURCE_CAPSULE, documentation)
        self.assertIn("never fetches the predecessor repository", documentation)
        self.assertIn("A cold Go", documentation)
        self.assertIn("GOPROXY=off", documentation)
        self.assertNotIn("requires no network access", documentation)
        self.assertIn("make round9-old-so-rollback-gate", workflow)
        self.assertNotIn("ROUND9_OLD_SO_VERIFY_REMOTE", workflow)


class RollbackHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.backup = self.root / "events.db.pre-v6-20260724T000000.000000000Z.bak"
        self.manifest = Path(str(self.backup) + ".manifest.json")
        self._create_v5_database(self.backup)
        os.chmod(self.backup, 0o400)
        self._write_manifest(self._manifest_value())

    def _create_v5_database(self, path: Path) -> None:
        with sqlite3.connect(path) as connection:
            connection.executescript(
                """
                CREATE TABLE schema_version (
                    singleton INTEGER PRIMARY KEY,
                    version INTEGER NOT NULL,
                    updated_at_ns INTEGER NOT NULL
                );
                INSERT INTO schema_version VALUES(1, 5, 1);
                CREATE TABLE audit_events (
                    id TEXT PRIMARY KEY,
                    disposition_placeholder TEXT
                );
                CREATE TABLE raw_request_captures (
                    id TEXT PRIMARY KEY,
                    raw_preview TEXT NOT NULL,
                    raw_sha256 TEXT NOT NULL
                );
                """
            )
            connection.execute(
                "INSERT INTO audit_events(id, disposition_placeholder) VALUES(?, '')",
                (SENTINEL_EVENT_ID,),
            )
            connection.execute(
                "INSERT INTO raw_request_captures(id, raw_preview, raw_sha256) VALUES(?, ?, ?)",
                (
                    SENTINEL_CAPTURE_ID,
                    SENTINEL_PREVIEW,
                    f"sha256:{SENTINEL_PREVIEW_SHA256}",
                ),
            )

    def _manifest_value(self) -> dict[str, object]:
        return {
            "schema": MANIFEST_SCHEMA,
            "database_file": self.backup.name,
            "source_schema_version": 5,
            "target_schema_version": 6,
            "created_at": "2026-07-24T00:00:00Z",
            "bytes": self.backup.stat().st_size,
            "sha256": f"sha256:{hashlib.sha256(self.backup.read_bytes()).hexdigest()}",
            "sqlite_quick_check": "ok",
            "exact_snapshot": True,
            "rollback_instruction": ROLLBACK_INSTRUCTION,
        }

    def _write_manifest(self, value: dict[str, object]) -> None:
        os.chmod(self.manifest, 0o600) if self.manifest.exists() else None
        self.manifest.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chmod(self.manifest, 0o400)

    def test_manifest_and_restore_are_byte_exact(self) -> None:
        verified = validate_manifest(self.backup, self.manifest)
        self.assertEqual(verified["source_schema_version"], 5)
        self.assertEqual(verified["target_schema_version"], 6)
        restore_dir = self.root / "restore"
        restore_dir.mkdir(mode=0o700)
        restored = restore_dir / "events.db"
        result = restore_backup(self.backup, self.manifest, restored)
        self.assertTrue(result["manifest_sha256_match"])
        self.assertEqual(result["quick_check"], "ok")
        self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)
        self.assertEqual(restored.read_bytes(), self.backup.read_bytes())
        self.assertEqual(inspect_database(restored, 5)["sentinel_capture_count"], 1)

    def test_manifest_contract_fails_closed_on_every_security_identity(self) -> None:
        mutations = (
            ("schema", "other"),
            ("database_file", "../events.db"),
            ("source_schema_version", 6),
            ("target_schema_version", 5),
            ("bytes", self.backup.stat().st_size + 1),
            ("sha256", "sha256:" + "0" * 64),
            ("sqlite_quick_check", "not ok"),
            ("exact_snapshot", False),
            ("rollback_instruction", "load the old SO directly"),
        )
        original = self._manifest_value()
        for key, value in mutations:
            with self.subTest(key=key):
                changed = dict(original)
                changed[key] = value
                self._write_manifest(changed)
                with self.assertRaises(GateError):
                    validate_manifest(self.backup, self.manifest)
        changed = dict(original)
        changed["unexpected"] = True
        self._write_manifest(changed)
        with self.assertRaises(GateError):
            validate_manifest(self.backup, self.manifest)

    def test_manifest_and_backup_modes_are_mandatory(self) -> None:
        os.chmod(self.backup, 0o600)
        with self.assertRaisesRegex(GateError, "backup mode"):
            validate_manifest(self.backup, self.manifest)
        os.chmod(self.backup, 0o400)
        os.chmod(self.manifest, 0o600)
        with self.assertRaisesRegex(GateError, "manifest mode"):
            validate_manifest(self.backup, self.manifest)

    def test_restore_refuses_overwrite(self) -> None:
        destination_dir = self.root / "occupied"
        destination_dir.mkdir(mode=0o700)
        destination = destination_dir / "events.db"
        destination.write_bytes(b"do not replace")
        with self.assertRaisesRegex(GateError, "already exists"):
            restore_backup(self.backup, self.manifest, destination)
        self.assertEqual(destination.read_bytes(), b"do not replace")


if __name__ == "__main__":
    unittest.main()
