#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "usage: $0 OUTPUT_FILE" >&2
  exit 2
fi

for required in openssl mktemp chmod ln dirname basename rm stat realpath id sync; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "required HMAC-key generation command not found: $required" >&2
    exit 127
  fi
done

output="$1"
directory="$(dirname -- "$output")"
name="$(basename -- "$output")"
if [[ "$name" == '.' || "$name" == '..' || "$name" == *$'\n'* || "$name" == *$'\r'* || "$directory" == *$'\n'* || "$directory" == *$'\r'* ]]; then
  echo "invalid HMAC key output name" >&2
  exit 2
fi
if [[ ! -d "$directory" || -L "$directory" ]]; then
  echo "HMAC key output directory must be an existing non-symlink directory: $directory" >&2
  exit 1
fi
resolved_directory="$(realpath -e -- "$directory")"
lexical_directory="$(realpath -m -s -- "$directory")"
if [[ "$resolved_directory" != "$lexical_directory" ]]; then
  echo "HMAC key output directory path must not contain symbolic links: $directory" >&2
  exit 1
fi
owner="$(stat -c '%u' -- "$resolved_directory")"
if [[ "$owner" != "$(id -u)" ]]; then
  echo "HMAC key output directory must be owned by the current user: $resolved_directory" >&2
  exit 1
fi
directory_permissions="$(stat -c '%a' -- "$resolved_directory")"
if (( (8#$directory_permissions & 0022) != 0 )); then
  echo "HMAC key output directory must not be group- or world-writable: $resolved_directory" >&2
  exit 1
fi
directory="$resolved_directory"
output="$directory/$name"
if [[ -e "$output" || -L "$output" ]]; then
  echo "refusing to overwrite existing HMAC key path: $output" >&2
  exit 1
fi

umask 077
temporary="$(mktemp "$directory/.${name}.tmp.XXXXXX")"
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "${temporary:-}" && -e "$temporary" ]]; then
    rm -f -- "$temporary"
  fi
  exit "$status"
}
trap cleanup EXIT

openssl rand -base64 48 > "$temporary"
chmod 0600 "$temporary"
if [[ "$(stat -c '%s' -- "$temporary")" != 65 ]]; then
  echo "generated HMAC key has an unexpected size" >&2
  exit 1
fi
if ! ln -- "$temporary" "$output"; then
  echo "refusing to replace HMAC key path created concurrently: $output" >&2
  exit 1
fi
if [[ "$(stat -c '%d:%i' -- "$temporary")" != "$(stat -c '%d:%i' -- "$output")" ]]; then
  echo "generated HMAC key publication identity mismatch" >&2
  exit 1
fi
rm -f -- "$temporary"
temporary=""
# A no-argument sync is specified by POSIX and flushes both the published file
# and its directory entry. Key generation is rare enough that the broader
# flush is preferable to depending on GNU-only sync -d/-f options.
sync

if [[ -L "$output" || ! -f "$output" ]]; then
  echo "generated HMAC key is not a regular file" >&2
  exit 1
fi
permissions="$(stat -c '%a' "$output" 2>/dev/null || true)"
if [[ "$permissions" != "600" ]]; then
  echo "generated HMAC key permissions are $permissions, expected 600" >&2
  exit 1
fi
echo "generated mode-0600 HMAC key: $output"
