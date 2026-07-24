#!/usr/bin/env bash
set -euo pipefail

binary="${PLUGIN_BINARY:?PLUGIN_BINARY is required}"
archive="${STORE_ARCHIVE:?STORE_ARCHIVE is required}"
source_date_epoch="${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}"

for command_name in install zip unzip mktemp touch rm mkdir basename dirname awk; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'required store-archive command not found: %s\n' "$command_name" >&2
    exit 127
  }
done

[[ -f "$binary" && ! -L "$binary" ]] || {
  printf 'store binary must be a regular non-symlink file: %s\n' "$binary" >&2
  exit 1
}
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || {
  printf 'SOURCE_DATE_EPOCH must be a non-negative integer\n' >&2
  exit 1
}

binary_name="$(basename "$binary")"
[[ "$binary_name" == *.so ]] || {
  printf 'store binary must use the Linux .so extension: %s\n' "$binary_name" >&2
  exit 1
}
archive_parent="$(dirname "$archive")"
mkdir -p "$archive_parent"
[[ -d "$archive_parent" && ! -L "$archive_parent" ]] || {
  printf 'store archive parent must be a real directory: %s\n' "$archive_parent" >&2
  exit 1
}
archive_parent="$(cd "$archive_parent" && pwd -P)"
archive="$archive_parent/$(basename "$archive")"

stage="$(mktemp -d)"
cleanup() {
  rm -rf -- "$stage"
}
trap cleanup EXIT

install -m 0755 "$binary" "$stage/$binary_name"
touch -h -d "@$source_date_epoch" "$stage/$binary_name"
rm -f -- "$archive"
(cd "$stage" && zip -X -q "$archive" "$binary_name")

listing="$(unzip -Z1 "$archive")"
[[ "$listing" == "$binary_name" ]] || {
  printf 'store archive must contain exactly one root dynamic library; got:\n%s\n' "$listing" >&2
  exit 1
}
mode="$(unzip -Z -l "$archive" | awk -v name="$binary_name" '$NF == name { count++; mode = $1 } END { if (count != 1) exit 1; print mode }')"
[[ "$mode" == -rwxr-xr-x ]] || {
  printf 'store archive dynamic library mode = %s, want -rwxr-xr-x\n' "$mode" >&2
  exit 1
}
