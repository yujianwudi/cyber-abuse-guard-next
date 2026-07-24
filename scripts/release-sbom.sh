#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
cyclonedx="${CYCLONEDX_GOMOD:-cyclonedx-gomod}"
expected_tool_version="${CYCLONEDX_GOMOD_VERSION:-v1.9.0}"
release_require_commands "$cyclonedx" git sed awk sha256sum sort date grep mkdir mktemp mv rm chmod
release_init

tool_version="$($cyclonedx version 2>&1)"
actual_tool_version="$(sed -nE 's/^[[:space:]]*Version:[[:space:]]*(v?[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*$/\1/p' <<<"$tool_version" | head -n 1)"
if [[ "v${actual_tool_version#v}" != "v${expected_tool_version#v}" ]]; then
	release_error "cyclonedx-gomod version mismatch: expected $expected_tool_version"
  printf '%s\n' "$tool_version" >&2
  exit 1
fi

output_dir="${OUTPUT_DIR:-$root/dist}"
mkdir -p "$output_dir"
raw="$(mktemp "$output_dir/.sbom-raw.XXXXXX")"
normalized="$(mktemp "$output_dir/.sbom-normalized.XXXXXX")"
trap 'rm -f -- "$raw" "$normalized"' EXIT
fixed_timestamp="$(date -u -d "@$RELEASE_SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"

(
  cd "$root"
  SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH" \
    "$cyclonedx" mod -json -noserial -output-version 1.6 -output "$raw" .
)
sed -E "s/(\"timestamp\"[[:space:]]*:[[:space:]]*\")[^\"]+(\")/\1$fixed_timestamp\2/" \
  "$raw" >"$normalized"

grep -Fq '"bomFormat": "CycloneDX"' "$normalized"
grep -Fq '"specVersion": "1.6"' "$normalized"
grep -Fq "\"timestamp\": \"$fixed_timestamp\"" "$normalized"
mv -f -- "$normalized" "$output_dir/sbom.cdx.json"
chmod 0644 "$output_dir/sbom.cdx.json"
rm -f -- "$raw"
trap - EXIT
release_assert_source_unchanged
printf 'CycloneDX SBOM: %s\n' "$output_dir/sbom.cdx.json"
