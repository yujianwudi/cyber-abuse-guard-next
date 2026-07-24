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
    def test_historical_source_is_fetched_only_from_predecessor_repository(self) -> None:
        root = Path(__file__).resolve().parent.parent
        script = (root / "scripts" / "round9-old-so-rollback-gate.sh").read_text(
            encoding="utf-8"
        )
        documentation = (root / "docs" / "ROUND9_OLD_SO_ROLLBACK_GATE.md").read_text(
            encoding="utf-8"
        )
        workflow = (root / ".github" / "workflows" / "round9-gate.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            f"historical_repository='{HISTORICAL_REPOSITORY}'", script
        )
        for required in (
            'git -C "$history_repo" remote add origin "$historical_repository"',
            'git -C "$history_repo" remote get-url origin',
            '"refs/tags/$historical_tag:refs/tags/$historical_tag"',
            'git -C "$history_repo" archive --format=tar "$historical_commit"',
            'git -C "$history_repo" show -s --format=%ct "$historical_commit"',
            'ls-remote --tags "$historical_repository"',
            "github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.Version",
            '--repository "$historical_repository"',
        ):
            self.assertIn(required, script)

        for forbidden in (
            'git -C "$root" archive',
            'git -C "$root" show -s --format=%ct "$historical_commit"',
            'ls-remote --tags origin',
            "github.com/yujianwudi/cyber-abuse-guard-next/internal/buildinfo.Version",
        ):
            self.assertNotIn(forbidden, script)

        self.assertIn(HISTORICAL_REPOSITORY, documentation)
        self.assertIn("never used as the source of the historical SO", documentation)
        self.assertIn("make round9-old-so-rollback-gate", workflow)


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
