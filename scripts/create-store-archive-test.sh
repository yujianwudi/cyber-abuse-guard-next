#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
go_bin="${GO:-go}"
for command_name in "$go_bin" sha256sum unzip grep awk mkdir chmod basename; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'required store-archive test command not found: %s\n' "$command_name" >&2
    exit 127
  }
done
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

binary="$work/cyber-abuse-guard-v0.15.so"
archive="$work/cyber-abuse-guard_0.15_linux_amd64.zip"
printf 'synthetic shared-object bytes for archive layout testing\n' >"$binary"
chmod 0755 "$binary"

PLUGIN_BINARY="$binary" STORE_ARCHIVE="$archive" SOURCE_DATE_EPOCH=1 \
  "$root/scripts/create-store-archive.sh"

[[ "$(unzip -Z1 "$archive")" == "$(basename "$binary")" ]]
if unzip -Z1 "$archive" | grep -q /; then
  echo "store archive unexpectedly contains a nested path" >&2
  exit 1
fi
[[ "$(unzip -Z -l "$archive" | awk -v name="$(basename "$binary")" '$NF == name { print $1 }')" == -rwxr-xr-x ]]

mkdir -p "$work/relative"
(
  cd "$work/relative"
  PLUGIN_BINARY="$binary" STORE_ARCHIVE=store.zip SOURCE_DATE_EPOCH=1 \
    "$root/scripts/create-store-archive.sh"
)
[[ -f "$work/relative/store.zip" ]]
[[ "$(unzip -Z1 "$work/relative/store.zip")" == "$(basename "$binary")" ]]

printf '{"version":"0.15"}\n' >"$work/build-metadata.json"
(
  cd "$work"
  sha256sum "$(basename "$archive")" >checksums.txt
)
DIST_DIR="$work" "$go_bin" -C "$root/integration/pluginstorecontract" test \
  -run '^TestPublishedStoreArchive$' -count=1 -v

echo "store archive layout test passed"
