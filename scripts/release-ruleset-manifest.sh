#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands git sed awk sha256sum sort mkdir mktemp mv rm chmod
release_init

output_dir="${OUTPUT_DIR:-$root/dist}"
mkdir -p "$output_dir"
temporary="$(mktemp "$output_dir/.ruleset-manifest.XXXXXX")"
trap 'rm -f -- "$temporary"' EXIT

mapfile -t rule_files < <(release_ruleset_files)
{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "plugin_version": "%s",\n' "$RELEASE_ARTIFACT_VERSION"
  printf '  "ruleset_version": "%s",\n' "$RELEASE_RULESET_VERSION"
  printf '  "ruleset_sha256": "%s",\n' "$RELEASE_RULESET_SHA256"
  printf '  "files": [\n'
  for index in "${!rule_files[@]}"; do
    file="${rule_files[$index]}"
    relative="${file#"$root"/}"
    hash="$(sha256sum "$file" | awk '{print $1}')"
    comma=,
    if ((index == ${#rule_files[@]} - 1)); then
      comma=
    fi
    printf '    {"path": "%s", "sha256": "%s"}%s\n' "$relative" "$hash" "$comma"
  done
  printf '  ]\n'
  printf '}\n'
} >"$temporary"

mv -f -- "$temporary" "$output_dir/ruleset-manifest.json"
(cd "$output_dir" && sha256sum ruleset-manifest.json >ruleset.sha256)
chmod 0644 "$output_dir/ruleset-manifest.json" "$output_dir/ruleset.sha256"
trap - EXIT
release_assert_source_unchanged
printf 'ruleset manifest: %s\n' "$output_dir/ruleset-manifest.json"
printf 'embedded ruleset SHA256: %s\n' "$RELEASE_RULESET_SHA256"
