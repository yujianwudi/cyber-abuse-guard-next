#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
fixture="$root/scripts/release-doc-consistency-test.sh"
gate="$root/scripts/release-doc-consistency.sh"
expected_fixture_sha256='cc6612262d965751fcc00a97a94d8db7349d4298589d1762778acac611bdcdf4'
expected_gate_sha256='868ddb61ffb7e68bced37ebcc765d1c233d1f81f09d766142c98947d1bebe924'

for required in sha256sum awk; do
  command -v "$required" >/dev/null 2>&1 || {
    printf '%s is required for the Round6 document fixture wrapper\n' "$required" >&2
    exit 127
  }
done
for path in "$fixture" "$gate"; do
  [[ -f "$path" && ! -L "$path" ]] || {
    printf 'Round6 document fixture dependency must be a regular non-symlink file\n' >&2
    exit 1
  }
done

fixture_sha256="$(sha256sum "$fixture" | awk '{print $1}')"
gate_sha256="$(sha256sum "$gate" | awk '{print $1}')"
[[ "$fixture_sha256" == "$expected_fixture_sha256" ]] || {
  printf 'Round6 document mutation fixture changed outside the reviewed contract\n' >&2
  exit 1
}
[[ "$gate_sha256" == "$expected_gate_sha256" ]] || {
  printf 'Round6 document consistency gate changed outside the reviewed contract\n' >&2
  exit 1
}

exec "$fixture"
