from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
import os
import stat
import struct
import sys
import tempfile
import unittest
import zlib
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))

import acquire
import supplemental_zip
from audit_contract import (
    EXPECTED_SEMANTIC_CASE_COUNT,
    EXPECTED_SUPPLEMENTAL_ZIP_CASE_COUNT,
    EXPECTED_SUPPLEMENTAL_ZIP_ENTRY_COUNT,
    FIXED_REPOSITORIES,
    SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY,
    SUPPLEMENTAL_ZIP_CLAIM_BOUNDARY,
    SUPPLEMENTAL_ZIP_MANIFEST_SCHEMA,
    ContractError,
    build_supplemental_execution_plan,
    validate_supplemental_manifest,
    validate_supplemental_policy,
)


POLICY_PATH = TOOL / "supplemental-zip-policy.json"


@dataclass
class SyntheticEntry:
    path: str
    content: bytes = b"benign inert review text\n"
    raw_name: bytes | None = None
    utf8: bool = True
    unicode_extra: bool = False
    duplicate_unicode_extra: bool = False
    unicode_version: int = 1
    unicode_crc: int | None = None
    flags: int = 0
    method: int = 8
    create_system: int = 0
    external_attributes: int | None = None
    header_crc: int | None = None
    zip64_extra: bool = False


def extra_field(field_id: int, value: bytes) -> bytes:
    return struct.pack("<HH", field_id, len(value)) + value


def raw_deflate(value: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    return compressor.compress(value) + compressor.flush()


def build_archive(
    entries: list[SyntheticEntry],
    *,
    prefix: bytes = b"",
    gap: bytes = b"",
    trailer: bytes = b"",
    disk_number: int = 0,
) -> tuple[bytes, list[dict[str, object]]]:
    local = bytearray(prefix)
    central_records: list[bytes] = []
    metadata: list[dict[str, object]] = []
    for index, entry in enumerate(entries):
        raw_name = entry.raw_name
        if raw_name is None:
            raw_name = entry.path.encode("utf-8")
        flags = entry.flags | (supplemental_zip.UTF8_FLAG if entry.utf8 else 0)
        crc = zlib.crc32(entry.content) & 0xFFFFFFFF
        header_crc = crc if entry.header_crc is None else entry.header_crc
        if entry.method == 0:
            payload = entry.content
        elif entry.method == 8:
            payload = raw_deflate(entry.content)
        else:
            payload = entry.content
        extras = b""
        unicode_body: bytes | None = None
        if entry.unicode_extra:
            name_crc = (
                zlib.crc32(raw_name) & 0xFFFFFFFF
                if entry.unicode_crc is None
                else entry.unicode_crc
            )
            unicode_body = (
                bytes([entry.unicode_version])
                + struct.pack("<L", name_crc)
                + entry.path.encode("utf-8")
            )
            extras += extra_field(supplemental_zip.UNICODE_PATH_EXTRA, unicode_body)
            if entry.duplicate_unicode_extra:
                extras += extra_field(
                    supplemental_zip.UNICODE_PATH_EXTRA, unicode_body
                )
        if entry.zip64_extra:
            extras += extra_field(supplemental_zip.ZIP64_EXTRA, b"\x00" * 8)
        local_offset = len(local)
        local_header = struct.pack(
            "<4s5H3L2H",
            supplemental_zip.LOCAL_SIGNATURE,
            20,
            flags,
            entry.method,
            0,
            0,
            header_crc,
            len(payload),
            len(entry.content),
            len(raw_name),
            len(extras),
        )
        data_offset = local_offset + len(local_header) + len(raw_name) + len(extras)
        local.extend(local_header)
        local.extend(raw_name)
        local.extend(extras)
        local.extend(payload)
        if index + 1 < len(entries):
            local.extend(gap)

        is_directory = entry.path.endswith("/")
        external = entry.external_attributes
        if external is None:
            external = 0x10 if is_directory else 0x20
        made_by = (entry.create_system << 8) | 20
        central = struct.pack(
            "<4s6H3L5H2L",
            supplemental_zip.CENTRAL_SIGNATURE,
            made_by,
            20,
            flags,
            entry.method,
            0,
            0,
            header_crc,
            len(payload),
            len(entry.content),
            len(raw_name),
            len(extras),
            0,
            0,
            0,
            external,
            local_offset,
        ) + raw_name + extras
        central_records.append(central)
        encoding = {
            "unicode_path_extra_name_crc32": (
                f"{(zlib.crc32(raw_name) & 0xFFFFFFFF if entry.unicode_crc is None else entry.unicode_crc):08x}"
                if entry.unicode_extra
                else None
            ),
            "unicode_path_extra_version": entry.unicode_version if entry.unicode_extra else None,
            "utf8_flag": entry.utf8,
        }
        normalized = (
            entry.content[3:]
            if entry.content.startswith(b"\xef\xbb\xbf")
            else entry.content
        ).replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        metadata.append(
            {
                "compressed_bytes": len(payload),
                "compression_method": entry.method,
                "content_sha256": hashlib.sha256(entry.content).hexdigest(),
                "crc32": f"{header_crc:08x}",
                "data_offset": data_offset,
                "encoding": encoding,
                "entry_id": f"entry-{index}",
                "flags": flags,
                "local_header_offset": local_offset,
                "normalized_text_sha256": hashlib.sha256(normalized).hexdigest(),
                "path": entry.path,
                "raw_name_sha256": hashlib.sha256(raw_name).hexdigest(),
                "text_bytes": len(normalized),
                "uncompressed_bytes": len(entry.content),
            }
        )

    directory_offset = len(local)
    central = b"".join(central_records)
    body = bytes(local) + central
    eocd = struct.pack(
        "<4s4H2LH",
        supplemental_zip.EOCD_SIGNATURE,
        disk_number,
        disk_number,
        len(entries),
        len(entries),
        len(central),
        directory_offset,
        0,
    )
    return body + eocd + trailer, metadata


def parser_policy(raw: bytes, metadata: list[dict[str, object]]) -> dict[str, object]:
    entries = []
    for item in metadata:
        entries.append(
            {
                key: item[key]
                for key in (
                    "compressed_bytes",
                    "compression_method",
                    "content_sha256",
                    "crc32",
                    "encoding",
                    "entry_id",
                    "normalized_text_sha256",
                    "path",
                    "raw_name_sha256",
                    "uncompressed_bytes",
                )
            }
        )
    return {
        "archive": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        "entries": entries,
    }


def reviewed_policy() -> tuple[dict[str, object], bytes]:
    raw = POLICY_PATH.read_bytes()
    return json.loads(raw), raw


def valid_manifest() -> tuple[dict[str, object], dict[str, object], bytes]:
    policy, policy_raw = reviewed_policy()
    policy = validate_supplemental_policy(policy, require_approved=True)
    approved = []
    for index, entry in enumerate(policy["entries"]):
        approved.append(
            {
                "compressed_bytes": entry["compressed_bytes"],
                "compression_method": entry["compression_method"],
                "content_sha256": entry["content_sha256"],
                "crc32": entry["crc32"],
                "data_offset": 1000 + index * 100000,
                "encoding": entry["encoding"],
                "entry_id": entry["entry_id"],
                "flags": 0,
                "local_header_offset": 900 + index * 100000,
                "normalized_text_sha256": entry["normalized_text_sha256"],
                "path": entry["path"],
                "raw_name_sha256": entry["raw_name_sha256"],
                "text_bytes": entry["uncompressed_bytes"],
                "uncompressed_bytes": entry["uncompressed_bytes"],
            }
        )
    archive = {
        **SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY,
        "aggregate_ratio_milli": 1745,
        "data_descriptor_entries": 0,
        "duplicate_normalized_names": 0,
        "duplicate_raw_names": 0,
        "encrypted_entries": 0,
        "max_entry_ratio_milli": 7734,
        "max_entry_uncompressed_bytes": 1673696,
        "special_entries": 0,
        "symlink_entries": 0,
        "unicode_path_entries": 681,
        "unsafe_paths": 0,
        "utf8_flag_entries": 0,
        "zip64_entries": 0,
    }
    policy_sha = hashlib.sha256(policy_raw).hexdigest()
    manifest = {
        "acquired_at": "2026-08-09T14:28:40Z",
        "approved_entries": approved,
        "archive": archive,
        "artifact_status": "candidate",
        "claim_boundary": SUPPLEMENTAL_ZIP_CLAIM_BOUNDARY,
        "code_executions": 0,
        "member_text_files_created": 0,
        "policy_review_status": "approved",
        "policy_sha256": policy_sha,
        "reviewed_cases": supplemental_zip._reviewed_cases(policy, approved),
        "schema": SUPPLEMENTAL_ZIP_MANIFEST_SCHEMA,
        "selected_entry_count": 4,
        "third_party_code_executions": 0,
        "unique_reviewed_cases": 7,
    }
    validate_supplemental_manifest(manifest, policy, policy_sha256=policy_sha)
    return manifest, policy, policy_raw


class SupplementalZipParserTests(unittest.TestCase):
    def inspect(self, entries: list[SyntheticEntry], **kwargs: object):
        raw, metadata = build_archive(entries, **kwargs)
        return supplemental_zip._inspect_archive_bytes(raw, parser_policy(raw, metadata))

    def test_accepts_efs_and_crc_bound_unicode_path_names(self) -> None:
        entries = [
            SyntheticEntry("safe/é.md", utf8=True),
            SyntheticEntry(
                "safe/quoted.txt",
                raw_name=b"safe/quoted.txt",
                utf8=False,
                unicode_extra=True,
            ),
        ]
        inspection = self.inspect(entries)
        self.assertEqual(set(inspection.selected_texts), {"entry-0", "entry-1"})
        self.assertEqual(inspection.archive["utf8_flag_entries"], 1)
        self.assertEqual(inspection.archive["unicode_path_entries"], 1)

    def test_rejects_missing_bad_or_conflicting_unicode_path_metadata(self) -> None:
        rejected = [
            SyntheticEntry("safe/name.md", raw_name=b"safe/name.md", utf8=False),
            SyntheticEntry(
                "safe/name.md",
                raw_name=b"safe/name.md",
                utf8=False,
                unicode_extra=True,
                unicode_version=2,
            ),
            SyntheticEntry(
                "safe/name.md",
                raw_name=b"safe/name.md",
                utf8=False,
                unicode_extra=True,
                unicode_crc=1,
            ),
            SyntheticEntry(
                "safe/name.md",
                raw_name=b"safe/name.md",
                utf8=False,
                unicode_extra=True,
                duplicate_unicode_extra=True,
            ),
            SyntheticEntry(
                "safe/name.md",
                raw_name=b"safe/other.md",
                utf8=True,
                unicode_extra=True,
            ),
            SyntheticEntry("safe/name.md", raw_name=b"safe/\xff.md", utf8=True),
            SyntheticEntry(
                "safe/name.md",
                raw_name=b"../hidden.md",
                utf8=False,
                unicode_extra=True,
            ),
            SyntheticEntry(
                "safe/name.md",
                raw_name=b"safe\\hidden.md",
                utf8=False,
                unicode_extra=True,
            ),
        ]
        for entry in rejected:
            with self.subTest(entry=entry), self.assertRaises(ContractError):
                self.inspect([entry])

    def test_rejects_prefix_trailer_gap_multidisk_zip64_and_flags(self) -> None:
        good = SyntheticEntry("safe/name.md")
        mutations = (
            ({"prefix": b"hidden"}, [good]),
            ({"trailer": b"hidden"}, [good]),
            ({"gap": b"hidden"}, [good, SyntheticEntry("safe/two.md")]),
            ({"disk_number": 1}, [good]),
            ({}, [SyntheticEntry("safe/name.md", zip64_extra=True)]),
            ({}, [SyntheticEntry("safe/name.md", flags=supplemental_zip.ENCRYPTED_FLAG)]),
            (
                {},
                [SyntheticEntry("safe/name.md", flags=supplemental_zip.DATA_DESCRIPTOR_FLAG)],
            ),
        )
        for options, entries in mutations:
            with self.subTest(options=options, entries=entries), self.assertRaises(
                ContractError
            ):
                self.inspect(entries, **options)

    def test_rejects_traversal_windows_unsafe_and_normalization_collisions(self) -> None:
        bad_paths = (
            "../escape.md",
            "/absolute.md",
            "C:/drive.md",
            "safe\\backslash.md",
            "safe/con.txt",
            "safe/trailing.",
            "safe/bidi\u202e.md",
            "safe/e\u0301.md",
        )
        for path in bad_paths:
            with self.subTest(path=path), self.assertRaises(ContractError):
                self.inspect([SyntheticEntry(path)])
        for entries in (
            [SyntheticEntry("safe/name.md"), SyntheticEntry("safe/name.md")],
            [SyntheticEntry("safe/Name.md"), SyntheticEntry("safe/name.md")],
            [SyntheticEntry("safe/K.md"), SyntheticEntry("safe/K.md")],
        ):
            with self.subTest(entries=entries), self.assertRaises(ContractError):
                self.inspect(entries)

    def test_rejects_symlink_special_method_ratio_crc_and_inert_text_failures(self) -> None:
        rejected = (
            SyntheticEntry(
                "safe/link.md",
                create_system=3,
                external_attributes=(stat.S_IFLNK | 0o777) << 16,
            ),
            SyntheticEntry("safe/method.md", method=12),
            SyntheticEntry("safe/ratio.md", content=b"A" * 10000),
            SyntheticEntry("safe/oversize.md", content=b"A" * (2 * 1024 * 1024 + 1)),
            SyntheticEntry(
                "safe/selected-oversize.md",
                content=hashlib.shake_256(b"selected oversize").digest(300000),
            ),
            SyntheticEntry("safe/crc.md", header_crc=1),
            SyntheticEntry("safe/nul.md", content=b"benign\x00text"),
            SyntheticEntry("safe/nonutf8.md", content=b"\xff"),
            SyntheticEntry(
                "safe/lfs.md",
                content=b"version https://git-lfs.github.com/spec/v1\n",
            ),
        )
        for entry in rejected:
            with self.subTest(entry=entry), self.assertRaises(ContractError):
                self.inspect([entry])

    def test_rejects_local_central_name_or_size_drift_and_overlap(self) -> None:
        raw, metadata = build_archive([SyntheticEntry("safe/name.md")])
        policy = parser_policy(raw, metadata)
        mutations = []
        local_name = bytearray(raw)
        local_name[30] ^= 1
        mutations.append(bytes(local_name))
        local_size = bytearray(raw)
        struct.pack_into("<L", local_size, 18, int(metadata[0]["compressed_bytes"]) + 1)
        mutations.append(bytes(local_size))
        unicode_raw, unicode_metadata = build_archive(
            [
                SyntheticEntry(
                    "safe/unicode.md",
                    raw_name=b"safe/unicode.md",
                    utf8=False,
                    unicode_extra=True,
                )
            ]
        )
        local_unicode = bytearray(unicode_raw)
        unicode_offset = local_unicode.find(struct.pack("<H", supplemental_zip.UNICODE_PATH_EXTRA))
        self.assertGreaterEqual(unicode_offset, 0)
        local_unicode[unicode_offset + 9] ^= 1
        unicode_policy = parser_policy(bytes(local_unicode), unicode_metadata)
        with self.assertRaises(ContractError):
            supplemental_zip._inspect_archive_bytes(bytes(local_unicode), unicode_policy)
        for mutation in mutations:
            mutation_policy = copy.deepcopy(policy)
            mutation_policy["archive"] = {
                "bytes": len(mutation),
                "sha256": hashlib.sha256(mutation).hexdigest(),
            }
            with self.subTest(), self.assertRaises(ContractError):
                supplemental_zip._inspect_archive_bytes(mutation, mutation_policy)

    def test_bound_input_rejects_symlink_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "input.zip"
            archive.write_bytes(b"not-a-zip")
            hardlink = root / "hardlink.zip"
            os.link(archive, hardlink)
            with self.assertRaisesRegex(ContractError, "hard link"):
                supplemental_zip._read_bound_archive(archive, 1024)
            hardlink.unlink()
            symlink = root / "symlink.zip"
            try:
                symlink.symlink_to(archive)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaises(ContractError):
                supplemental_zip._read_bound_archive(symlink, 1024)


class SupplementalContractTests(unittest.TestCase):
    def test_reviewed_policy_is_closed_and_core_denominator_is_unchanged(self) -> None:
        policy, _ = reviewed_policy()
        policy = validate_supplemental_policy(policy, require_approved=True)
        self.assertEqual(len(policy["entries"]), EXPECTED_SUPPLEMENTAL_ZIP_ENTRY_COUNT)
        self.assertEqual(
            sum(len(entry["semantic_cases"]) for entry in policy["entries"]),
            EXPECTED_SUPPLEMENTAL_ZIP_CASE_COUNT,
        )
        self.assertEqual(EXPECTED_SEMANTIC_CASE_COUNT, 19)
        self.assertEqual(len(FIXED_REPOSITORIES), 5)
        expected = {
            "authorized-ctf": ("allow", "allow", "allow"),
            "defensive": ("allow", "allow", "allow"),
            "activated": (
                "allow",
                "block_malicious_text",
                "block_malicious_text",
            ),
        }
        for entry in policy["entries"]:
            for case in entry["semantic_cases"]:
                actions = case["expected_action_by_mode"]
                self.assertEqual(
                    (actions["audit"], actions["balanced"], actions["strict"]),
                    expected[case["id_suffix"]],
                )

    def test_manifest_and_independent_plan_are_closed(self) -> None:
        manifest, policy, policy_raw = valid_manifest()
        validated = validate_supplemental_manifest(
            manifest,
            policy,
            policy_sha256=hashlib.sha256(policy_raw).hexdigest(),
        )
        plan = build_supplemental_execution_plan(validated, 1205, 3)
        self.assertEqual(len(plan), 7 * 3 * 2 * 2 * 3)
        self.assertTrue(
            all(item.semantic_case_id.startswith("supplemental-zip:") for item in plan)
        )
        self.assertEqual(EXPECTED_SEMANTIC_CASE_COUNT, 19)

    def test_manifest_rejects_text_files_execution_and_case_drift(self) -> None:
        manifest, policy, policy_raw = valid_manifest()
        policy_sha = hashlib.sha256(policy_raw).hexdigest()
        for field in (
            "code_executions",
            "member_text_files_created",
            "third_party_code_executions",
        ):
            mutation = copy.deepcopy(manifest)
            mutation[field] = 1
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_supplemental_manifest(
                    mutation, policy, policy_sha256=policy_sha
                )
        mutation = copy.deepcopy(manifest)
        mutation["reviewed_cases"].pop()
        mutation["unique_reviewed_cases"] = 6
        with self.assertRaises(ContractError):
            validate_supplemental_manifest(mutation, policy, policy_sha256=policy_sha)

    def test_metadata_only_acquire_validate_and_discard_preserve_archive(self) -> None:
        manifest, _policy, _policy_raw = valid_manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "operator.zip"
            archive.write_bytes(b"operator-owned archive sentinel")
            output = root / "candidate"
            with mock.patch(
                "acquire.create_supplemental_manifest", return_value=manifest
            ):
                acquired = acquire.acquire_supplemental_zip(
                    archive, POLICY_PATH, output
                )
            self.assertEqual(acquired, manifest)
            self.assertEqual(
                [path.name for path in output.iterdir()],
                [acquire.SUPPLEMENTAL_MANIFEST_NAME],
            )
            self.assertEqual(archive.read_bytes(), b"operator-owned archive sentinel")
            manifest_path = output / acquire.SUPPLEMENTAL_MANIFEST_NAME
            acquire.validate_supplemental_candidate(manifest_path, POLICY_PATH)
            self.assertEqual(
                acquire.discard_supplemental_candidate(manifest_path, POLICY_PATH), 1
            )
            self.assertFalse(output.exists())
            self.assertEqual(archive.read_bytes(), b"operator-owned archive sentinel")

    def test_cli_supplemental_arguments_are_all_or_none_and_mutually_exclusive(self) -> None:
        parsed = acquire.parse_args(
            [
                "--supplemental-archive",
                "archive.zip",
                "--supplemental-policy",
                "policy.json",
                "--output",
                "candidate",
            ]
        )
        self.assertEqual(parsed.supplemental_zip, Path("archive.zip"))
        rejected = (
                ["--supplemental-archive", "archive.zip", "--output", "candidate"],
                ["--supplemental-archive", "archive.zip", "--supplemental-policy", "policy.json"],
            ["--policy", "core.json", "--supplemental-policy", "policy.json", "--output", "candidate"],
            ["--discard-candidate", "manifest.json", "--output", "candidate"],
        )
        for argv in rejected:
            with (
                self.subTest(argv=argv),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                acquire.parse_args(argv)


if __name__ == "__main__":
    unittest.main()
