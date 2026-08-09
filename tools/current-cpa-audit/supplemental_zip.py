#!/usr/bin/env python3
"""Parse one reviewed supplemental ZIP without extracting or executing it.

The central and local headers are parsed from the same descriptor-bound byte
string.  Only policy-selected Markdown/TXT members are decompressed, and those
bytes remain in memory.
"""

from __future__ import annotations

import os
import re
import stat
import struct
import unicodedata
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from audit_contract import (
    EXPECTED_SUPPLEMENTAL_ZIP_CASE_COUNT,
    EXPECTED_SUPPLEMENTAL_ZIP_ENTRY_COUNT,
    SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY,
    SUPPLEMENTAL_ZIP_CLAIM_BOUNDARY,
    SUPPLEMENTAL_ZIP_LIMITS,
    SUPPLEMENTAL_ZIP_MANIFEST_SCHEMA,
    TEMPLATE_SHA256,
    ContractError,
    fail,
    open_regular,
    sha256_bytes,
    supplemental_review_sha256,
    validate_inert_text,
    validate_supplemental_case,
    validate_supplemental_manifest,
    validate_supplemental_policy,
)


LOCAL_SIGNATURE = b"PK\x03\x04"
CENTRAL_SIGNATURE = b"PK\x01\x02"
EOCD_SIGNATURE = b"PK\x05\x06"
ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
UNICODE_PATH_EXTRA = 0x7075
ZIP64_EXTRA = 0x0001
UTF8_FLAG = 0x0800
ENCRYPTED_FLAG = 0x0001
DATA_DESCRIPTOR_FLAG = 0x0008
ALLOWED_FLAGS = UTF8_FLAG
WINDOWS_RESERVED = {
    "aux",
    "clock$",
    "con",
    "nul",
    "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
DRIVE_PATH = re.compile(r"[A-Za-z]:")
BIDI_CONTROLS = {
    "\u061c",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


@dataclass(frozen=True)
class ParsedEntry:
    path: str
    raw_name: bytes
    flags: int
    compression_method: int
    crc32: int
    compressed_bytes: int
    uncompressed_bytes: int
    local_header_offset: int
    data_offset: int
    data_end: int
    is_directory: bool
    encoding: dict[str, Any]


@dataclass(frozen=True)
class SupplementalInspection:
    archive: dict[str, Any]
    approved_entries: list[dict[str, Any]]
    selected_texts: dict[str, bytes]


def _ratio_milli(uncompressed: int, compressed: int) -> int:
    if uncompressed == 0:
        return 0
    if compressed == 0:
        fail("supplemental ZIP contains a zero-byte compressed non-empty entry")
    return (uncompressed * 1000 + compressed - 1) // compressed


def _parse_extras(raw: bytes, label: str) -> list[tuple[int, bytes]]:
    result: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(raw):
        if offset + 4 > len(raw):
            fail(f"{label} has a truncated extra-field header")
        field_id, size = struct.unpack_from("<HH", raw, offset)
        offset += 4
        if offset + size > len(raw):
            fail(f"{label} has a truncated extra-field body")
        result.append((field_id, raw[offset : offset + size]))
        offset += size
    return result


def _unicode_path(
    raw_name: bytes, flags: int, extras: list[tuple[int, bytes]], label: str
) -> tuple[str, dict[str, Any], bytes | None]:
    unicode_fields = [value for field_id, value in extras if field_id == UNICODE_PATH_EXTRA]
    if len(unicode_fields) > 1:
        fail(f"{label} repeats the Info-ZIP Unicode Path field")
    unicode_raw = unicode_fields[0] if unicode_fields else None
    unicode_name: str | None = None
    name_crc32: str | None = None
    if unicode_raw is not None:
        if len(unicode_raw) < 6 or unicode_raw[0] != 1:
            fail(f"{label} has an invalid Info-ZIP Unicode Path version or body")
        expected_crc = int.from_bytes(unicode_raw[1:5], "little")
        observed_crc = zlib.crc32(raw_name) & 0xFFFFFFFF
        if expected_crc != observed_crc:
            fail(f"{label} Info-ZIP Unicode Path CRC does not bind the raw filename")
        try:
            unicode_name = unicode_raw[5:].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            fail(f"{label} Info-ZIP Unicode Path is not UTF-8 at byte {exc.start}")
        name_crc32 = f"{expected_crc:08x}"

    if flags & UTF8_FLAG:
        try:
            decoded = raw_name.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            fail(f"{label} EFS filename is not UTF-8 at byte {exc.start}")
        if unicode_name is not None and unicode_name != decoded:
            fail(f"{label} EFS and Unicode Path filenames conflict")
        encoding = {
            "unicode_path_extra_name_crc32": name_crc32,
            "unicode_path_extra_version": 1 if unicode_raw is not None else None,
            "utf8_flag": True,
        }
        return decoded, encoding, unicode_raw

    if unicode_name is None or name_crc32 is None:
        fail(f"{label} lacks unambiguous UTF-8 filename metadata")
    encoding = {
        "unicode_path_extra_name_crc32": name_crc32,
        "unicode_path_extra_version": 1,
        "utf8_flag": False,
    }
    return unicode_name, encoding, unicode_raw


def _validate_path(path: str, is_directory: bool, label: str) -> str:
    if not path or "\x00" in path or "\\" in path:
        fail(f"{label} is empty or contains NUL/backslash")
    if path.startswith(("/", "//")) or DRIVE_PATH.match(path):
        fail(f"{label} is absolute")
    if is_directory != path.endswith("/"):
        fail(f"{label} directory marker differs from its file type")
    normalized_path = path[:-1] if is_directory else path
    if not normalized_path or path != unicodedata.normalize("NFC", path):
        fail(f"{label} is empty after normalization or is not NFC")
    encoded = path.encode("utf-8")
    if len(encoded) > SUPPLEMENTAL_ZIP_LIMITS["max_path_utf8_bytes"]:
        fail(f"{label} exceeds the UTF-8 path byte bound")
    parts = normalized_path.split("/")
    if (
        len(parts) > SUPPLEMENTAL_ZIP_LIMITS["max_path_depth"]
        or any(part in {"", ".", ".."} for part in parts)
    ):
        fail(f"{label} has unsafe depth or traversal components")
    for part in parts:
        if len(part.encode("utf-8")) > SUPPLEMENTAL_ZIP_LIMITS["max_path_component_utf8_bytes"]:
            fail(f"{label} contains an oversized component")
        if part.endswith((" ", ".")) or any(character in '<>:"|?*' for character in part):
            fail(f"{label} contains a Windows-unsafe component")
        if any(
            ord(character) < 32
            or 0x7F <= ord(character) <= 0x9F
            or character in BIDI_CONTROLS
            for character in part
        ):
            fail(f"{label} contains control or bidirectional formatting characters")
        reserved_key = part.split(".", 1)[0].casefold()
        if reserved_key in WINDOWS_RESERVED:
            fail(f"{label} contains a reserved Windows component")
    return path


def _validate_raw_path(raw_name: bytes, is_directory: bool, label: str) -> None:
    if (
        not raw_name
        or len(raw_name) > SUPPLEMENTAL_ZIP_LIMITS["max_path_utf8_bytes"]
        or b"\x00" in raw_name
        or b"\\" in raw_name
        or raw_name.startswith(b"/")
        or raw_name.endswith(b"/") != is_directory
    ):
        fail(f"{label} raw filename has an unsafe absolute or separator form")
    normalized = raw_name[:-1] if is_directory else raw_name
    parts = normalized.split(b"/")
    if (
        len(parts) > SUPPLEMENTAL_ZIP_LIMITS["max_path_depth"]
        or any(part in {b"", b".", b".."} for part in parts)
    ):
        fail(f"{label} raw filename has traversal or unsafe depth")
    for part in parts:
        if (
            len(part) > SUPPLEMENTAL_ZIP_LIMITS["max_path_component_utf8_bytes"]
            or part.endswith((b" ", b"."))
            or any(byte < 32 or byte == 127 for byte in part)
            or any(character in part for character in b'<>:"|?*')
        ):
            fail(f"{label} raw filename contains an unsafe component")
        try:
            ascii_part = part.decode("ascii").casefold()
        except UnicodeDecodeError:
            continue
        if ascii_part.split(".", 1)[0] in WINDOWS_RESERVED:
            fail(f"{label} raw filename contains a reserved component")


def _read_bound_archive(path: Path, maximum: int) -> bytes:
    descriptor, opened = open_regular(
        path, "supplemental ZIP input", require_single_link=True
    )
    if not 1 <= opened.st_size <= maximum:
        os.close(descriptor)
        fail("supplemental ZIP input size is outside the reviewed bound")
    opened_identity = (opened.st_dev, opened.st_ino)
    chunks: list[bytes] = []
    total = 0
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            while True:
                chunk = handle.read(min(1024 * 1024, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    fail("supplemental ZIP input grew beyond the reviewed byte bound")
            after = os.fstat(handle.fileno())
            if (
                (after.st_dev, after.st_ino) != opened_identity
                or after.st_nlink != 1
                or after.st_size != opened.st_size
                or total != opened.st_size
            ):
                fail("supplemental ZIP descriptor identity or size drifted while reading")
    except BaseException:
        raise
    try:
        named = path.lstat()
    except FileNotFoundError:
        fail("supplemental ZIP input disappeared after the bound read")
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or (named.st_dev, named.st_ino) != opened_identity
        or named.st_nlink != 1
        or named.st_size != opened.st_size
    ):
        fail("supplemental ZIP path identity drifted during the bound read")
    return b"".join(chunks)


def _find_eocd(raw: bytes) -> tuple[int, tuple[Any, ...]]:
    if len(raw) < 22:
        fail("supplemental ZIP is shorter than an EOCD record")
    lower = max(0, len(raw) - (65_535 + 22))
    candidates: list[tuple[int, tuple[Any, ...]]] = []
    cursor = lower
    while True:
        offset = raw.find(EOCD_SIGNATURE, cursor)
        if offset < 0:
            break
        if offset + 22 <= len(raw):
            values = struct.unpack_from("<4s4H2LH", raw, offset)
            if offset + 22 + values[-1] == len(raw):
                candidates.append((offset, values))
        cursor = offset + 1
    if len(candidates) != 1:
        fail("supplemental ZIP does not contain one exact terminal EOCD")
    return candidates[0]


def _decompress_selected(raw: bytes, entry: ParsedEntry, maximum: int) -> bytes:
    payload = raw[entry.data_offset : entry.data_end]
    if len(payload) != entry.compressed_bytes:
        fail(f"selected ZIP entry payload is truncated: {entry.path}")
    if entry.compression_method == 0:
        extracted = payload
    elif entry.compression_method == 8:
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        output = bytearray()
        pending = payload
        while pending:
            remaining = maximum + 1 - len(output)
            if remaining <= 0:
                fail(f"selected ZIP entry exceeds the expansion bound: {entry.path}")
            output.extend(decoder.decompress(pending, remaining))
            if len(output) > maximum:
                fail(f"selected ZIP entry exceeds the expansion bound: {entry.path}")
            pending = decoder.unconsumed_tail
            if not pending:
                break
        remaining = maximum + 1 - len(output)
        output.extend(decoder.flush(max(1, remaining)))
        if (
            len(output) > maximum
            or not decoder.eof
            or decoder.unused_data
            or decoder.unconsumed_tail
        ):
            fail(f"selected ZIP entry has an invalid or overlong DEFLATE stream: {entry.path}")
        extracted = bytes(output)
    else:  # pragma: no cover - the parser closes this before selection
        fail(f"selected ZIP entry uses an unsupported compression method: {entry.path}")
    if len(extracted) != entry.uncompressed_bytes:
        fail(f"selected ZIP entry expanded size differs from its header: {entry.path}")
    if zlib.crc32(extracted) & 0xFFFFFFFF != entry.crc32:
        fail(f"selected ZIP entry CRC differs from its header: {entry.path}")
    return extracted


def _normalize_selected_text(raw: bytes, label: str) -> bytes:
    inert = validate_inert_text(
        raw, label, SUPPLEMENTAL_ZIP_LIMITS["max_selected_entry_bytes"]
    )
    text = inert.decode("utf-8", "strict")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    if not 1 <= len(normalized) <= SUPPLEMENTAL_ZIP_LIMITS["max_selected_entry_bytes"]:
        fail(f"{label} normalization produced an invalid byte length")
    return normalized


def inspect_supplemental_zip(
    archive_path: Path, policy_value: Any
) -> SupplementalInspection:
    policy = validate_supplemental_policy(policy_value, require_approved=True)
    raw = _read_bound_archive(
        archive_path, SUPPLEMENTAL_ZIP_LIMITS["max_archive_bytes"]
    )
    return _inspect_archive_bytes(raw, policy)


def _inspect_archive_bytes(
    raw: bytes, policy: Mapping[str, Any]
) -> SupplementalInspection:
    """Testable byte parser; callers must validate policy before production use."""

    try:
        return _inspect_archive_bytes_impl(raw, policy)
    except ContractError:
        raise
    except (OverflowError, struct.error, UnicodeError, zlib.error) as exc:
        fail(f"supplemental ZIP structure is invalid: {type(exc).__name__}")


def _inspect_archive_bytes_impl(
    raw: bytes, policy: Mapping[str, Any]
) -> SupplementalInspection:

    if sha256_bytes(raw) != policy["archive"]["sha256"] or len(raw) != policy["archive"]["bytes"]:
        fail("supplemental ZIP bytes differ from the reviewed archive identity")
    if not raw.startswith(LOCAL_SIGNATURE):
        fail("supplemental ZIP has a prefix or lacks a first local header")
    eocd_offset, eocd = _find_eocd(raw)
    (
        _,
        disk_number,
        directory_disk,
        entries_on_disk,
        total_entries,
        directory_size,
        directory_offset,
        comment_length,
    ) = eocd
    if (
        disk_number != 0
        or directory_disk != 0
        or entries_on_disk != total_entries
        or total_entries in {0, 0xFFFF}
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
    ):
        fail("supplemental ZIP is empty, multi-disk, or uses ZIP64 EOCD fields")
    if total_entries > SUPPLEMENTAL_ZIP_LIMITS["max_entry_count"]:
        fail("supplemental ZIP entry count exceeds the reviewed bound")
    if directory_offset + directory_size != eocd_offset:
        fail("supplemental ZIP central directory does not end exactly at EOCD")
    if raw[directory_offset : directory_offset + 4] != CENTRAL_SIGNATURE:
        fail("supplemental ZIP central directory offset is invalid")
    if (
        raw[max(0, eocd_offset - 20) : eocd_offset - 16] == ZIP64_LOCATOR_SIGNATURE
        or raw[max(0, directory_offset - 56) : directory_offset - 52]
        == ZIP64_EOCD_SIGNATURE
    ):
        fail("supplemental ZIP contains ZIP64 control records")

    selected_policy = {entry["path"]: entry for entry in policy["entries"]}
    selected_entries: dict[str, ParsedEntry] = {}
    parsed_entries: list[ParsedEntry] = []
    raw_names: set[bytes] = set()
    decoded_names: set[str] = set()
    compatibility_names: set[str] = set()
    local_offsets: set[int] = set()
    total_compressed = 0
    total_uncompressed = 0
    stored_entries = 0
    deflated_entries = 0
    directory_count = 0
    file_count = 0
    utf8_flag_entries = 0
    unicode_path_entries = 0
    maximum_entry_bytes = 0
    maximum_entry_ratio = 0

    cursor = directory_offset
    for index in range(total_entries):
        label = f"supplemental ZIP central entry[{index}]"
        if cursor + 46 > eocd_offset:
            fail(f"{label} header is truncated")
        values = struct.unpack_from("<4s6H3L5H2L", raw, cursor)
        if values[0] != CENTRAL_SIGNATURE:
            fail(f"{label} signature is invalid")
        (
            _,
            version_made_by,
            version_needed,
            flags,
            method,
            _mod_time,
            _mod_date,
            crc32,
            compressed_bytes,
            uncompressed_bytes,
            name_length,
            extra_length,
            entry_comment_length,
            starting_disk,
            _internal_attributes,
            external_attributes,
            local_header_offset,
        ) = values
        end = cursor + 46 + name_length + extra_length + entry_comment_length
        if end > eocd_offset or name_length == 0:
            fail(f"{label} variable fields are truncated or empty")
        raw_name = raw[cursor + 46 : cursor + 46 + name_length]
        extra_raw = raw[
            cursor + 46 + name_length : cursor + 46 + name_length + extra_length
        ]
        if entry_comment_length != 0:
            fail(f"{label} contains an ambiguous per-entry comment")
        extras = _parse_extras(extra_raw, f"{label}.extra")
        if any(field_id == ZIP64_EXTRA for field_id, _ in extras):
            fail(f"{label} uses a ZIP64 extra field")
        if version_needed > 20 or starting_disk != 0:
            fail(f"{label} requires an unsupported ZIP version or disk")
        if flags & ENCRYPTED_FLAG:
            fail(f"{label} is encrypted")
        if flags & DATA_DESCRIPTOR_FLAG:
            fail(f"{label} uses a data descriptor")
        if flags & ~ALLOWED_FLAGS:
            fail(f"{label} uses unsupported general-purpose flags")
        if method not in SUPPLEMENTAL_ZIP_LIMITS["allowed_compression_methods"]:
            fail(f"{label} uses an unsupported compression method")
        if uncompressed_bytes > SUPPLEMENTAL_ZIP_LIMITS["max_entry_uncompressed_bytes"]:
            fail(f"{label} exceeds the per-entry expansion bound")
        ratio = _ratio_milli(uncompressed_bytes, compressed_bytes)
        if ratio > SUPPLEMENTAL_ZIP_LIMITS["max_entry_ratio_milli"]:
            fail(f"{label} exceeds the per-entry compression-ratio bound")
        decoded, encoding, unicode_extra = _unicode_path(raw_name, flags, extras, label)
        is_directory = decoded.endswith("/")
        _validate_raw_path(raw_name, is_directory, f"{label}.raw_filename")
        _validate_path(decoded, is_directory, f"{label}.filename")

        create_system = version_made_by >> 8
        dos_attributes = external_attributes & 0xFF
        if dos_attributes & 0x08:
            fail(f"{label} is a DOS volume entry")
        if create_system == 0:
            if bool(dos_attributes & 0x10) != is_directory:
                fail(f"{label} DOS directory type differs from its filename")
        elif create_system == 3:
            unix_mode = (external_attributes >> 16) & 0xFFFF
            file_type = stat.S_IFMT(unix_mode)
            allowed_type = (0, stat.S_IFDIR) if is_directory else (0, stat.S_IFREG)
            if file_type not in allowed_type:
                fail(f"{label} is a symlink or special Unix file")
        else:
            fail(f"{label} uses an unsupported creator operating system")
        if is_directory and (compressed_bytes != 0 or uncompressed_bytes != 0):
            fail(f"{label} directory contains a payload")

        if raw_name in raw_names:
            fail(f"{label} repeats raw filename bytes")
        collision_name = decoded.rstrip("/")
        if collision_name in decoded_names:
            fail(f"{label} repeats a decoded/NFC filename")
        compatibility_name = unicodedata.normalize("NFKC", collision_name).casefold()
        if compatibility_name in compatibility_names:
            fail(f"{label} collides after NFKC/casefold normalization")
        raw_names.add(raw_name)
        decoded_names.add(collision_name)
        compatibility_names.add(compatibility_name)
        if local_header_offset in local_offsets or local_header_offset >= directory_offset:
            fail(f"{label} repeats or escapes its local-header offset")
        local_offsets.add(local_header_offset)

        if local_header_offset + 30 > directory_offset:
            fail(f"{label} local header is truncated")
        local = struct.unpack_from("<4s5H3L2H", raw, local_header_offset)
        if local[0] != LOCAL_SIGNATURE:
            fail(f"{label} local header signature is invalid")
        (
            _,
            local_version_needed,
            local_flags,
            local_method,
            _local_mod_time,
            _local_mod_date,
            local_crc32,
            local_compressed_bytes,
            local_uncompressed_bytes,
            local_name_length,
            local_extra_length,
        ) = local
        local_name_start = local_header_offset + 30
        local_data_offset = local_name_start + local_name_length + local_extra_length
        if local_data_offset > directory_offset:
            fail(f"{label} local variable fields are truncated")
        local_name = raw[local_name_start : local_name_start + local_name_length]
        local_extra_raw = raw[
            local_name_start + local_name_length : local_data_offset
        ]
        local_extras = _parse_extras(local_extra_raw, f"{label}.local_extra")
        if any(field_id == ZIP64_EXTRA for field_id, _ in local_extras):
            fail(f"{label} local header uses a ZIP64 extra field")
        local_unicode = [
            value for field_id, value in local_extras if field_id == UNICODE_PATH_EXTRA
        ]
        if (
            local_version_needed != version_needed
            or local_flags != flags
            or local_method != method
            or local_crc32 != crc32
            or local_compressed_bytes != compressed_bytes
            or local_uncompressed_bytes != uncompressed_bytes
            or local_name != raw_name
            or len(local_unicode) != (1 if unicode_extra is not None else 0)
            or (unicode_extra is not None and local_unicode[0] != unicode_extra)
        ):
            fail(f"{label} local and central identities differ")
        data_end = local_data_offset + compressed_bytes
        if data_end > directory_offset:
            fail(f"{label} compressed payload overlaps the central directory")

        parsed = ParsedEntry(
            path=decoded,
            raw_name=raw_name,
            flags=flags,
            compression_method=method,
            crc32=crc32,
            compressed_bytes=compressed_bytes,
            uncompressed_bytes=uncompressed_bytes,
            local_header_offset=local_header_offset,
            data_offset=local_data_offset,
            data_end=data_end,
            is_directory=is_directory,
            encoding=encoding,
        )
        parsed_entries.append(parsed)
        if decoded in selected_policy:
            if is_directory:
                fail(f"allowlisted supplemental ZIP entry is a directory: {decoded}")
            selected_entries[decoded] = parsed
        total_compressed += compressed_bytes
        total_uncompressed += uncompressed_bytes
        stored_entries += int(method == 0)
        deflated_entries += int(method == 8)
        directory_count += int(is_directory)
        file_count += int(not is_directory)
        utf8_flag_entries += int(bool(flags & UTF8_FLAG))
        unicode_path_entries += int(unicode_extra is not None)
        maximum_entry_bytes = max(maximum_entry_bytes, uncompressed_bytes)
        maximum_entry_ratio = max(maximum_entry_ratio, ratio)
        cursor = end

    if cursor != directory_offset + directory_size:
        fail("supplemental ZIP central directory length differs from EOCD")
    if total_uncompressed > SUPPLEMENTAL_ZIP_LIMITS["max_total_uncompressed_bytes"]:
        fail("supplemental ZIP aggregate expansion exceeds the reviewed bound")
    aggregate_ratio = _ratio_milli(total_uncompressed, total_compressed)
    if aggregate_ratio > SUPPLEMENTAL_ZIP_LIMITS["max_aggregate_ratio_milli"]:
        fail("supplemental ZIP aggregate compression ratio exceeds the reviewed bound")
    ranges = sorted(
        (entry.local_header_offset, entry.data_end, entry.path) for entry in parsed_entries
    )
    if not ranges or ranges[0][0] != 0 or ranges[-1][1] != directory_offset:
        fail("supplemental ZIP has a prefix or gap before its central directory")
    for previous, current in zip(ranges, ranges[1:]):
        if previous[1] != current[0]:
            fail("supplemental ZIP local records overlap or contain hidden gaps")
    if set(selected_entries) != set(selected_policy):
        fail("supplemental ZIP does not contain the exact four allowlisted paths")

    archive_summary = {
        "aggregate_ratio_milli": aggregate_ratio,
        "bytes": len(raw),
        "central_directory_bytes": directory_size,
        "central_directory_offset": directory_offset,
        "data_descriptor_entries": 0,
        "deflated_entries": deflated_entries,
        "directory_count": directory_count,
        "duplicate_normalized_names": 0,
        "duplicate_raw_names": 0,
        "encrypted_entries": 0,
        "entry_compressed_bytes": total_compressed,
        "entry_count": total_entries,
        "eocd_comment_bytes": comment_length,
        "file_count": file_count,
        "max_entry_ratio_milli": maximum_entry_ratio,
        "max_entry_uncompressed_bytes": maximum_entry_bytes,
        "sha256": sha256_bytes(raw),
        "special_entries": 0,
        "stored_entries": stored_entries,
        "symlink_entries": 0,
        "unicode_path_entries": unicode_path_entries,
        "uncompressed_bytes": total_uncompressed,
        "unsafe_paths": 0,
        "utf8_flag_entries": utf8_flag_entries,
        "zip64_entries": 0,
    }
    for key, expected in policy["archive"].items():
        if archive_summary[key] != expected:
            fail(f"supplemental ZIP observed archive summary differs at {key}")

    approved_entries: list[dict[str, Any]] = []
    selected_texts: dict[str, bytes] = {}
    selected_total = 0
    for policy_entry in policy["entries"]:
        entry = selected_entries[policy_entry["path"]]
        extracted = _decompress_selected(
            raw, entry, SUPPLEMENTAL_ZIP_LIMITS["max_selected_entry_bytes"]
        )
        normalized = _normalize_selected_text(
            extracted, f"supplemental ZIP selected text {policy_entry['entry_id']}"
        )
        observed = {
            "compressed_bytes": entry.compressed_bytes,
            "compression_method": entry.compression_method,
            "content_sha256": sha256_bytes(extracted),
            "crc32": f"{entry.crc32:08x}",
            "data_offset": entry.data_offset,
            "encoding": entry.encoding,
            "entry_id": policy_entry["entry_id"],
            "flags": entry.flags,
            "local_header_offset": entry.local_header_offset,
            "normalized_text_sha256": sha256_bytes(normalized),
            "path": entry.path,
            "raw_name_sha256": sha256_bytes(entry.raw_name),
            "text_bytes": len(normalized),
            "uncompressed_bytes": entry.uncompressed_bytes,
        }
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
        ):
            if observed[key] != policy_entry[key]:
                fail(
                    f"supplemental ZIP allowlisted entry {policy_entry['entry_id']} differs at {key}"
                )
        approved_entries.append(observed)
        selected_texts[policy_entry["entry_id"]] = normalized
        selected_total += len(normalized)
    if selected_total > SUPPLEMENTAL_ZIP_LIMITS["max_selected_total_bytes"]:
        fail("supplemental ZIP selected normalized text exceeds the aggregate bound")
    return SupplementalInspection(archive_summary, approved_entries, selected_texts)


def _reviewed_cases(
    policy: Mapping[str, Any], approved_entries: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    approved = {entry["entry_id"]: entry for entry in approved_entries}
    reviewer = policy["reviewer"]
    result: list[dict[str, Any]] = []
    for policy_entry in policy["entries"]:
        entry = approved[policy_entry["entry_id"]]
        for ground_truth in policy_entry["semantic_cases"]:
            case = {
                "authorization": ground_truth["authorization"],
                "current_action": ground_truth["current_action"],
                "expected_action_by_mode": ground_truth["expected_action_by_mode"],
                "id": (
                    f"supplemental-zip:{entry['entry_id']}:"
                    f"{ground_truth['id_suffix']}"
                ),
                "label": ground_truth["label"],
                "label_reason": ground_truth["label_reason"],
                "ownership": ground_truth["ownership"],
                "reviewer": {
                    "identity": reviewer["identity"],
                    "review_sha256": None,
                    "reviewed_at": reviewer["reviewed_at"],
                    "status": reviewer["status"],
                },
                "source": {
                    "archive_sha256": SUPPLEMENTAL_ZIP_ARCHIVE_IDENTITY["sha256"],
                    "content_sha256": entry["content_sha256"],
                    "entry_id": entry["entry_id"],
                    "normalized_text_sha256": entry["normalized_text_sha256"],
                    "path": entry["path"],
                    "text_bytes": entry["text_bytes"],
                },
                "template": {
                    "id": ground_truth["template_id"],
                    "sha256": TEMPLATE_SHA256[ground_truth["template_id"]],
                },
            }
            case["reviewer"]["review_sha256"] = supplemental_review_sha256(case)
            validate_supplemental_case(case, f"supplemental reviewed case {case['id']}")
            result.append(case)
    if len(result) != EXPECTED_SUPPLEMENTAL_ZIP_CASE_COUNT:
        fail("supplemental ZIP policy did not produce exactly seven cases")
    return result


def create_supplemental_manifest(
    archive_path: Path,
    policy_value: Any,
    policy_sha256: str,
    acquired_at: str,
) -> dict[str, Any]:
    policy = validate_supplemental_policy(policy_value, require_approved=True)
    inspection = inspect_supplemental_zip(archive_path, policy)
    manifest = {
        "acquired_at": acquired_at,
        "approved_entries": inspection.approved_entries,
        "archive": inspection.archive,
        "artifact_status": "candidate",
        "claim_boundary": SUPPLEMENTAL_ZIP_CLAIM_BOUNDARY,
        "code_executions": 0,
        "member_text_files_created": 0,
        "policy_review_status": policy["reviewer"]["status"],
        "policy_sha256": policy_sha256,
        "reviewed_cases": _reviewed_cases(policy, inspection.approved_entries),
        "schema": SUPPLEMENTAL_ZIP_MANIFEST_SCHEMA,
        "selected_entry_count": len(inspection.approved_entries),
        "third_party_code_executions": 0,
        "unique_reviewed_cases": EXPECTED_SUPPLEMENTAL_ZIP_CASE_COUNT,
    }
    validate_supplemental_manifest(
        manifest, policy, policy_sha256=policy_sha256
    )
    return manifest


def load_selected_supplemental_texts(
    archive_path: Path,
    policy_value: Any,
    manifest_value: Any | None = None,
    *,
    policy_sha256: str | None = None,
) -> dict[str, bytes]:
    """Return only the four reviewed normalized texts, without writing them."""

    policy = validate_supplemental_policy(policy_value, require_approved=True)
    inspection = inspect_supplemental_zip(archive_path, policy)
    if manifest_value is not None:
        manifest = validate_supplemental_manifest(
            manifest_value, policy, policy_sha256=policy_sha256
        )
        if (
            manifest["archive"] != inspection.archive
            or manifest["approved_entries"] != inspection.approved_entries
        ):
            fail("supplemental ZIP bytes differ from the supplied validated manifest")
    if len(inspection.selected_texts) != EXPECTED_SUPPLEMENTAL_ZIP_ENTRY_COUNT:
        fail("supplemental ZIP loader did not return exactly four selected texts")
    return dict(inspection.selected_texts)


__all__ = [
    "SupplementalInspection",
    "create_supplemental_manifest",
    "inspect_supplemental_zip",
    "load_selected_supplemental_texts",
]
